# Stack Canary LLVM Pass

This project implements a **stack canary** security feature using an **LLVM Pass**, targeting **x86 binaries**.

## Overview

The stack canary mechanism is a protection against stack buffer overflows. This implementation enhances security by injecting custom prologue and epilogue code into every function to:

- **Generate a random canary value** at process startup.
- **Store the canary in a global variable.**
- **Push the canary onto the stack** at function entry (prologue).
- **Check the canary before returning** from the function (epilogue). If the value is corrupted, a SIGABRT is triggered.

## Features

- Works on **x86 architecture**.
- **Random canary** generation for each execution.
- Injects protection code via an **LLVM IR transformation**.
- Detects stack smashing before function returns.