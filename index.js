var whois = require('node-whois');
var changeCase = require('change-case');
var os = require('os');
var availabilityChecks = require('./availability-checks.json');

require('es6-shim')

var log = console.log.bind(console);

function parseRawData(rawData) {
    var result = {};
    var lines = rawData.split(os.EOL);

    lines.forEach(function(line){
        line = line.trim();
        if ( line && (line.includes(': ') || line.includes(':\t')) ) {
            var lineParts = line.split(':');

            // greater than since lines often have more than one colon, eg values with URLS
            if ( lineParts.length >= 2 ) {
                var keyName = changeCase.camelCase(lineParts[0]);
                result[keyName] = lineParts.splice(1).join(':').trim();
            }
        }
    });

    return result;
}

module.exports = function(domain, options, cb){

    if ( typeof cb === 'undefined' && typeof options === 'function' ) {
        cb = options;
        options = {};
    }

    whois.lookup(domain, options, function(err, rawData) {

        if ( err ) {
            return cb(err, null);
        }

        var result = {};

        if ( typeof rawData == 'object' ) {
            result = rawData.map(function(data) {
                var raw = data.data;

                data.data = parseRawData(raw);

                if (options.verbose) {
                    data.raw = raw;

                    var checks = availabilityChecks[data.server.host];
                    if (checks) {
                        data.data.isAvailable = -1 !== raw.indexOf(checks);
                    }
                }
                return data;
            });
        } else {
            result = parseRawData(rawData, options);
        }

        cb(null, result);
    });
}


