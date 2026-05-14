// test-worker.js
// Web Worker for running WASM proof functions with threading support

// Console interception — forwards timing and log events to main thread
(function setupWorkerConsoleCapture() {
    const originalTime = console.time;
    const originalTimeEnd = console.timeEnd;
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    const timers = new Map();

    console.time = function(label = 'default') {
        timers.set(label, performance.now());
        self.postMessage({
            type: 'console',
            message: `Timer '${label}' started`,
            data: { type: 'time', label }
        });
        return originalTime.apply(this, arguments);
    };

    console.timeEnd = function(label = 'default') {
        const startTime = timers.get(label);
        const endTime = performance.now();
        if (startTime !== undefined) {
            const duration = endTime - startTime;
            timers.delete(label);
            self.postMessage({
                type: 'timeEnd',
                message: `${label}: ${duration.toFixed(3)}ms`,
                data: { label, duration: `${duration.toFixed(3)}ms`, durationMs: duration }
            });
        }
        return originalTimeEnd.apply(this, arguments);
    };

    console.log = function(...args) {
        const message = args.map(arg =>
            typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
        ).join(' ');
        self.postMessage({ type: 'console', message, data: { type: 'log' } });
        return originalLog.apply(this, arguments);
    };

    console.error = function(...args) {
        const message = args.map(arg =>
            typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
        ).join(' ');
        self.postMessage({ type: 'console', message, data: { type: 'error' } });
        return originalError.apply(this, arguments);
    };

    console.warn = function(...args) {
        const message = args.map(arg =>
            typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
        ).join(' ');
        self.postMessage({ type: 'console', message, data: { type: 'warn' } });
        return originalWarn.apply(this, arguments);
    };
})();

let wasmModule;
let wasmInitialized = false;

async function initializeWasm(threadCount = null) {
    try {
        console.log('Worker: Starting WASM initialization...');
        console.time('wasm_total_init');

        wasmModule = await import('/pkg/intmax3_zkp.js');
        console.log('Worker: WASM module imported');

        await wasmModule.default();
        console.log('Worker: WASM module initialized');

        const numThreads = threadCount || navigator.hardwareConcurrency || 4;
        console.log(`Worker: Initializing thread pool with ${numThreads} threads...`);

        console.time('wasm_thread_pool_init');
        await wasmModule.initThreadPool(numThreads);
        console.timeEnd('wasm_thread_pool_init');

        // Initialize GPU Merkle if available
        let gpuEnabled = false;
        try {
            gpuEnabled = await wasmModule.init_gpu_merkle();
            console.log(`Worker: GPU Merkle ${gpuEnabled ? 'initialized' : 'not available (CPU-only build)'}`);
        } catch (e) {
            console.warn('Worker: GPU init failed:', e);
        }

        console.timeEnd('wasm_total_init');
        wasmInitialized = true;

        self.postMessage({
            type: 'ready',
            message: `WASM initialized with ${numThreads} threads`,
            data: { threadCount: numThreads, gpuEnabled }
        });

    } catch (error) {
        console.error('Worker: Failed to initialize WASM:', error);
        self.postMessage({
            type: 'error',
            error: error.toString(),
            data: { function: 'initialization' }
        });
    }
}

self.onmessage = async function(e) {
    const { action, threadCount } = e.data;

    if (action === 'init') {
        await initializeWasm(threadCount);
        return;
    }

    if (!wasmInitialized || !wasmModule) {
        self.postMessage({
            type: 'error',
            error: 'WASM not initialized yet',
            data: { function: action }
        });
        return;
    }

    try {
        let startTime = performance.now();

        switch (action) {
            case 'run_single_withdrawal_proof':
                self.postMessage({ type: 'log', message: 'Starting run_single_withdrawal_proof()...' });
                console.time('run_single_withdrawal_proof');
                await wasmModule.run_single_withdrawal_proof();
                console.timeEnd('run_single_withdrawal_proof');
                self.postMessage({
                    type: 'result',
                    data: {
                        function: 'run_single_withdrawal_proof',
                        duration: `${(performance.now() - startTime).toFixed(2)}ms`
                    }
                });
                break;

            case 'run_balance_processor_flow':
                self.postMessage({ type: 'log', message: 'Starting run_balance_processor_flow()...'});
                console.time('run_balance_processor_flow');
                await wasmModule.run_balance_processor_flow();
                console.timeEnd('run_balance_processor_flow');
                self.postMessage({
                    type: 'result',
                    data: {
                        function: 'run_balance_processor_flow',
                        duration: `${(performance.now() - startTime).toFixed(2)}ms`,
                    }
                });
                break;
            default:
                self.postMessage({
                    type: 'error',
                    error: `Unknown action: ${action}`,
                    data: { function: action }
                });
        }

    } catch (error) {
        console.error(`Worker: Error executing ${action}:`, error);
        self.postMessage({
            type: 'error',
            error: error.toString(),
            data: { function: action }
        });
    }
};

self.onerror = function(error) {
    console.error('Worker: Unhandled error:', error);
    self.postMessage({
        type: 'error',
        error: error.toString(),
        data: { function: 'worker' }
    });
};
