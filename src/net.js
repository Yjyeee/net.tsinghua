var jsdom = require('jsdom');
var request = require('request');
var dgram = require('dgram');
var md5 = require('md5');
var Uint64LE = require("int64-buffer").Uint64LE;

var utils = require('./utils');

var BASE_URL = 'https://net.tsinghua.edu.cn';
var STATUS_URL = BASE_URL + '/rad_user_info.php';
var WEB_LOGIN_URL = BASE_URL + '/do_login.php';
var SRUN_LOGIN_URL = 'http://166.111.204.120:69/cgi-bin/srun_portal';

var USER_AGENT = 'Unknown';
if (process.platform === 'darwin')
USER_AGENT = 'Mozilla/5.0 (Mac OS X)';
else if (process.platform === 'win32')
USER_AGENT = 'Windows NT';
else if (process.platform === 'linux')
USER_AGENT = 'Linux';


// Call callback(err).
exports.login = function login(use_srun, username, md5_pass, callback) {
    if (typeof callback === 'undefined') {
        callback = function (err) {};
    }
    if (use_srun) {
        srun_login(username, md5_pass, utils.getmac(), callback);
    } else {
        web_login(username, md5_pass, callback);
    }
}

function srun_login(username, md5_pass, mac, callback) {
    var udp = dgram.createSocket('udp4');

    udp.on('listening', function() {
        console.log('listening');
    });
    function get_salt(username) {
        var head = Buffer.from([0x9c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        var msg = Buffer.concat([head, Buffer.from(username)], 56);
        udp.send(msg, 0, 56, 3335,'166.111.204.120', function (err) {
        });
    }

    udp.on('message', function (msg, info) {
        var user_id = new Uint64LE(msg.slice(8,16));
        var v1 = Buffer.from([user_id & 255]);
        var temp = Buffer.concat([v1, Buffer.from(md5_pass), msg.slice(16,32)]);
        var password = md5(temp);

        request.post({
            url: SRUN_LOGIN_URL,
            form: {
                action: 'login',
                username: username,
                password: password,
                // password: '{MD5_HEX}' + md5_pass,
                chap: 1,
                drop: 0,
                n: 120,
                pop: 1,
                type: 6,
                mac: mac,
                ac_id: 1
            },
            // encoding: null,
            headers: {'User-Agent': USER_AGENT}
        },
        function (err, r, body) {
            body = utils.gb2312_to_utf8(body);
            udp.close();
            if (err) {
                console.error('Error while logging in: %s.', err);
                callback(err);
            } else if (body.startsWith('login_ok')) {
                console.info('Logged in using %s', username);
                callback(null);
            } else {
                console.error('Failed to login: %s', body);
                callback(body);
            }
        });
    });
    get_salt(username);
}

// Call callback(err).
exports.logout = function logout(use_srun, username, callback) {
    // FIXME: Ugly, use || or something to fix it?
    if (typeof callback === 'undefined') {
        callback = function (err) {};
    }
    if (use_srun) {
        srun_logout(username, utils.getmac(), callback);
    } else {
        web_logout(username, callback);
    }
}
function srun_logout(username, mac, callback) {

    request.post({
        url: SRUN_LOGIN_URL,
        form: {
            ac_id: 1,
            mac: mac,
            type: 6,
            username: username,
            action: 'logout'
        }
    },
    function (err, r, body) {
        if (err) {
            console.error('Error while logging out: %s.', err);
            callback(err);
        } else if (body === 'logout_ok') {
            console.info('Logged out.');
            callback(null);
        } else {
            console.error('Failed to logout: %s', body);
            callback(body);
        }
    }
    );
}
function web_login(username, md5_pass, callback) {
    request.post({
        url: WEB_LOGIN_URL,
        form: {
            action: 'login',
            username: username,
            password: '{MD5_HEX}' + md5_pass,
            ac_id: 1
        },
        encoding: null,
        headers: {'User-Agent': USER_AGENT}
    },
    function (err, r, body) {
        body = utils.gb2312_to_utf8(body);
        if (err) {
            console.error('Error while logging in: %s.', err);
            callback(err);
        } else if (body === 'Login is successful.') {
            console.info('Logged in using %s', username);
            callback(null);
        } else {
            console.error('Failed to login: %s', body);
            callback(body);
        }
    });
}
function web_logout(username, callback) {
    request.post({
        url: WEB_LOGIN_URL,
        form: {
            action: 'logout'
        }
    },
    function (err, r, body) {
        if (err) {
            console.error('Error while logging out: %s.', err);
            callback(err);
        } else if (body === 'Logout is successful.') {
            console.info('Logged out.');
            callback(null);
        } else {
            console.error('Failed to logout: %s', body);
            callback(body);
        }
    });
}
// Call callback(err, infos).
exports.get_status = function get_status(callback) {
    if (typeof callback === 'undefined') {
        callback = function (err, infos) {};
    }

    request(STATUS_URL, function (err, r, body) {
        if (err) {
            console.error('Error while getting status: %s', err);
            callback(err);
        } else {
            var infos;
            if (body) {
                var info_strs = body.split(',');
                infos = {
                    username: info_strs[0],
                    start_time: new Date(Number(info_strs[1]) * 1000),
                    usage: Number(info_strs[3]),
                    total_usage: Number(info_strs[6]),
                    ip: info_strs[8],
                    balance: Number(info_strs[11])
                };
            } else {
                infos = null;
            }
            console.log('Got status: %s', JSON.stringify(infos));
            callback(null, infos);
        }
    });
}
