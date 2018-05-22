import { spawn } from "child_process";

function spawnAndReadlines(path: string, args: string[], fn: (line: string) => boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        const child = spawn(path, args, {
            stdio: [ "inherit", "pipe", "inherit" ]
        });
        let remainder = "";
        child.stdout.on("data", (data: string|Buffer) => {
            remainder += data;
            for (;;) {
                const eol = remainder.indexOf("\n");
                if (eol < 0)
                    return;
                if (!fn(remainder.substr(0, eol))) {
                    child.kill();
                    throw new Error("fn returned false");
                }
                remainder = remainder.substr(eol + 1);
            }
        });
        child.stdout.on("end", () => {
            if (remainder !== "" && !fn(remainder))
                throw new Error("fn returned false");
        })
        child.on("error", (err: Error) => {
            throw err;
        });
        child.on("exit", (code: number, signal: string) => {
            if (signal)
                process.stderr.write(`Caught signal '${signal}'\n`);
            if (code)
                reject(`code: ${code}`);
            else
                resolve();
        })
    });
}

// var i = 0;
// spawnAndReadlines("seq", [ "10" ], (line) => {
//     process.stdout.write(`line ${i++}: '${line}'\n`);
//     return true;
// }).catch((reason: any) => {
//     process.stderr.write(`Caught exception:\n${reason}\n`);
//     process.exit(1);
// });

// First, parse the command-line (#0 = node, #1 = this script path)
if (process.argv.length != 3) {
    process.stderr.write(`Need 1 argument: the ELF binary\n`);
    process.exit(1);
}
const elfBinary = process.argv[2];

// This class contains the entry point and the list of function addresses
class Functions {
    private _entryPoint: number = -1;
    private addresses: number[] = [];
    private sorted: boolean = true;
    private map = new Map<number, string>();

    public get entryPoint(): number {
        if (this._entryPoint < 0)
            throw new Error("Entry point undefined!");
        return this._entryPoint;
    }

    public set entryPoint(address: number) {
        if (this._entryPoint >= 0)
            throw new Error("Duplicate entry point");
        this._entryPoint = address;
    }

    public add(address: number, name: string): void {
        // silently ignore `UND` symbols (address 0x0)
        if (address === 0)
            return;

        const n = this.addresses.length;
        if (n > 0) {
            const previous = this.addresses[n - 1];
            if (previous === address)
                // ignore duplicates
                return;
            if (previous > address)
                this.sorted = false;
        } 

        this.addresses.push(address);
        this.map.set(address, name);
    }

    public lookup(address: number): string|undefined {
        if (!this.sorted) {
            this.addresses.sort((a: number, b: number) => {
                return a - b;
            });
            this.sorted = true;
        }

        // binary search
        let left = -1;
        let right = this.addresses.length;

        while (left + 1 < right) {
            const middle = (left + right) >> 1;
            if (this.addresses[middle] > address)
                right = middle;
            else
                left = middle;
        }
        if (left < 0)
            return undefined;
        return this.map.get(this.addresses[left]);
    }
}

class CallGraph {
    private caller2callees = new Map<string, Set<string>>();
    private callee2callers = new Map<string, Set<string>>();

    public add(caller: string, callee: string) {
//if (callee === "die") console.log(`got caller ${caller}`);
        const callees = this.caller2callees.get(caller) || new Set<string>();
        callees.add(callee);
        if (callees.size === 1)
            this.caller2callees.set(caller, callees);

        const callers = this.callee2callers.get(callee) || new Set<string>();
        callers.add(caller);
        if (callers.size === 1)
            this.callee2callers.set(callee, callers);
    }

    public getCallersOf(callee: string): string[] {
        const result: string[] = [];
        const callers = this.callee2callers.get(callee);
        if (callers !== undefined)
            callers.forEach((value: string) => {
                result.push(value);
            });
        result.sort();
        return result;
    }
    public getCalleesOf(callee: string): string[] {
        const result: string[] = [];
        const callees = this.caller2callees.get(callee);
        if (callees !== undefined)
            callees.forEach((value: string) => {
                result.push(value);
            });
        result.sort();
        return result;
    }
}

// Then, parse the output of readelf/objdump
let functions = new Functions();
let callGraph = new CallGraph();

let inSymTab = false;
spawnAndReadlines("readelf", [ elfBinary, "--headers", "--symbols" ], (line: string): boolean => {
    let match = line.match(/Entry point address:\s*(0x[0-9a-f]+)/);
    if (match) {
        functions.entryPoint = parseInt(match[1], 16);
        return true;
    }

    match = line.match(/^[A-Z]/);
    if (match) {
        inSymTab = line.indexOf(".symtab") > 0;
        return true;
    }
    
    if (inSymTab) {
        match = line.match(/^\s*\d+:\s*([0-9a-f]+)\s+[0-9]+\s+\S+\s+\S+\s+\S+\s+\d+\s+(.*)/);
        if (match) {
            functions.add(parseInt(match[1], 16), match[2]);
        }
    }

    return true;
}).then(() => {
    return spawnAndReadlines("objdump", [ "-D", "-b", "binary", "-mi386:x86-64", elfBinary ], (line: string): boolean => {
        const match = line.match(/^\s*([0-9a-f]+):.*\b(callq|jmpq|jmp|je|jne|jg|jge|jl|jle)\b.*\b0x([0-9a0-f]+)$/);
        if (!match)
            return true;
        const caller = functions.lookup(parseInt(match[1], 16));
        if (caller === undefined)
            return true;
        const callee = functions.lookup(parseInt(match[3], 16));
        if (callee !== undefined)
            callGraph.add(caller, callee);
        return true;
    });
}).then(() => {
    const todo: string[] = [];
    const callees = new Set<string>();
    todo.push("get_oid");
    while (todo.length > 0) {
        const name = todo.pop();
        callGraph.getCalleesOf(name!).forEach((value: string) => {
            if (callees.has(value))
                return;
            todo.push(value);
            callees.add(value);
        });
    }

    const callers: string[] = [];
    callGraph.getCallersOf("die").forEach((value) => {
        if (callees.has(value))
           callers.push(value);
    });
    console.log(`done: callers of 'die': ${callers}`);
}).catch((reason: any) => {
    process.stderr.write(`Caught exception:\n${reason}\n`);
});
