'use strict';
// Structured JSON logging. Every line is a single JSON object so logs are machine-parseable
// (DESIGN.md §5.3). No secrets are ever logged — callers must pass digests/ids, not key material.

function emit(level, fields) {
  const rec = { ts: new Date().toISOString(), level, ...fields };
  const line = JSON.stringify(rec);
  if (level === 'error' || level === 'warn') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
  return rec;
}

module.exports = {
  info: (fields) => emit('info', fields),
  warn: (fields) => emit('warn', fields),
  error: (fields) => emit('error', fields),
  debug: (fields) => (process.env.NODE_DEBUG_INTMAX ? emit('debug', fields) : null),
};
