## Why I Built This

While studying how malware works and how systems detect it, I realized something important: to build truly stealthy software, you have to understand exactly how security tools think and catch threats. 

I didn't just want to read about endpoint defense—I wanted to look at the battlefield from the other side. I built this custom EDR engine from scratch to get a deep, low-level understanding of process monitoring and memory security. Moving forward, this project will serve as my own local lab where I can stress-test my custom tools against real security controls and learn how to write quieter, smarter software.


## What the Tool Does

At its core, My Custom EDR is a lightweight security monitor that acts like a specialized guard for a running application. 

Instead of waiting for a file to run on the hard drive, this tool watches the application's live memory inside a native Windows debugging loop. When a new module or DLL tries to inject itself into the process space, the tool halts execution instantly to inspect it. 

It checks the file's path for spoofing, verifies its digital blueprint against a list of known threat signatures, and parses its internal headers to make sure it is safe. If the engine catches a threat, it doesn't just crash the main program. Instead, it surgically rewrites a tiny piece of the loading DLL's memory, causing the module to fail quietly and allowing the main application to keep running without missing a beat.

## The Subsystem Layout & Code Architecture

The engine is built around clean **Object-Oriented Programming** rules. Instead of using messy, scattered scripts, all process tracking states, detection routines, and memory patches are completely organized inside a single, reusable class profile called `EDR_Engine`.

* **Automatic Cleanup:** System handles and background debug hooks are tied directly to the class lifespan. When the monitoring session ends, the engine's cleanup system (`~EDR_Engine`) automatically closes all open process connections. This ensures the tool never leaks system memory or locks resources by accident.
* **Smart String Management:** The engine uses overloaded building blocks to automatically accept both classic text formats (`LPCSTR`) and native Windows wide characters (`LPCWSTR`). Because Windows processes strings in wide characters natively, this approach cuts down on internal data conversions, making the tracking loop faster.

## The Blueprint Configuration (`EDR_Engine.h`)

The header file serves as the main blueprint for the security tool. It sets up strict privacy walls to keep the application stable and utilizes fast built-in data layouts:

* **Instant Signature Matching:** The tool tracks malicious files using an `std::unordered_set`. This keeps threat lookup times constant, meaning the engine can immediately recognize a known bad file hash without slowing down the app it is trying to protect.
* **Strict Structural Separation:** All dangerous or heavy inner actions—like streaming file hashes (`hash_file`), checking folder paths, and writing memory patches—are locked behind a `private` security wall. The rest of the project can only see simple, safe controls like starting the tracking engine (`.monitor()`) or printing diagnostics (`.show_process_info()`).
* **Fast Cryptographic Analysis:** The header pulls in native Windows security libraries (`bcrypt.lib`). Instead of adding bulky third-party code to calculate file hashes, the engine drops directly into the operating system's built-in hashing tools to quickly identify threats.
