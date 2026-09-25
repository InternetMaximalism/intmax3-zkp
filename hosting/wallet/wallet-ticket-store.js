'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function readTicketsFile(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const tickets = JSON.parse(raw);
  if (!Array.isArray(tickets) || tickets.some(t => !t || typeof t.id !== 'string'
      || typeof t.type !== 'string' || typeof t.status !== 'string'
      || !t.params || typeof t.params !== 'object' || Array.isArray(t.params))) {
    throw new Error('Saved operation records are invalid; refusing to start another operation.');
  }
  return tickets;
}

function writeTicketsFile(file, tickets) {
  const temp = file + '.' + crypto.randomUUID() + '.tmp';
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(tickets, null, 2));
    fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.renameSync(temp, file);
    const dir = fs.openSync(path.dirname(file), 'r');
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temp, {force:true});
  }
}
module.exports = {readTicketsFile, writeTicketsFile};
