'use strict';

// Shared shim for the node/API tree. The implementation lives next to the wallet relay because
// that directory is also the self-contained EC2 deployment bundle.
module.exports = require('../../hosting/wallet/public-backing');
