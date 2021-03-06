const jsdom = require("jsdom");
const { JSDOM } = jsdom;
var fs = require('fs');
var path = require('path');

var CERT_LIST = [fs.readFileSync(path.join(__dirname, '../certificate/2ac1f2ba.0')),
fs.readFileSync(path.join(__dirname, '../certificate/5ad8a5d6.0'))];

var request = require('request').defaults({
  jar: true,
  agentOptions: { ca: CERT_LIST }
});

var utils = require('./utils');

var BASE_URL = 'http://usereg.tsinghua.edu.cn';
var LOGIN_URL = BASE_URL + '/do.php';
var INFO_URL = BASE_URL + '/user_info.php';
var SESSIONS_URL = BASE_URL + '/online_user_ipv4.php';

// Call callback(err, infos).
// infos:
// {
//   usage: ...,
//   balance: ...,
//   sessions: [...]
// }
exports.get_infos = function get_infos(username, md5_pass, callback) {
  if (typeof callback === 'undefined') {
    callback = function (err, infos) { };
  }

  login(username, md5_pass, function (err) {
    if (err) {
      callback(err);
    } else {
      // Logged into usereg, fetch user page.
      request({ url: INFO_URL, encoding: null }, function (err, r, info_page) {
        if (err) {
          console.error('Error while fetching user info from usereg: %s', err);
          callback(err);
        } else {
          // User page fetched, fetch sessions page.
          request({ url: SESSIONS_URL, encoding: null }, function (err, r, sessions_page) {
            if (err) {
              console.error('Error while fetching sessions from usereg: %s', err);
              callback(err);
            } else {
              // Pages fetched, parse them.
              parse_pages(info_page, sessions_page, callback);
            }
          });
        }
      });
    }
  });
}

// Call callback(err).
exports.logout_session = function logout_session(username, md5_pass, id, callback) {
  if (typeof callback === 'undefined') {
    callback = function (err) { };
  }

  login(username, md5_pass, function (err) {
    if (err) {
      callback(err);
    } else {
      // Logged into usereg, logout session.
      request.post({
        url: SESSIONS_URL,
        form: {
          action: 'drops',
          user_ip: id + ','
        },
        encoding: null
      },
        function (err, r, body) {
          body = utils.gb2312_to_utf8(body);
          if (err) {
            console.error('Error while logging out session %s: %s', id, err);
            callback(err);
          } else if (body == '下线请求已发送') {
            console.log('Request to log out session %s sent', id);
            callback(null);
          } else {
            console.error('Failed to send logout request for session %s: %s',
              id, body);
            callback(body);
          }
        });
    }
  });
}

// Call callback(err).
function login(username, md5_pass, callback) {
  if (typeof callback === 'undefined') {
    callback = function (err) { };
  }

  request.post({
    url: LOGIN_URL,
    form: {
      action: 'login',
      user_login_name: username,
      user_password: md5_pass
    },
    encoding: null
  },
    function (err, r, body) {
      body = utils.gb2312_to_utf8(body);
      if (err) {
        console.error('Error while logging into usereg: %s', err);
        callback(err);
      } else if (body == 'ok') {
        console.info('Logged into usereg using %s', username);
        callback(null);
      } else {
        console.error('Failed to login to usereg: %s', body);
        callback(body);
      }
    }
  );
}

// Call callback(err, infos).
// TODO: catch errors.
function parse_pages(info_page, sessions_page, callback) {
  if (typeof callback === 'undefined') {
    callback = function (err, infos) { };
  }

  info_page = utils.gb2312_to_utf8(info_page);
  sessions_page = utils.gb2312_to_utf8(sessions_page);

  var infos = {};

  // Parse info page.
  (function () {
    const dom = new JSDOM(info_page, {'url': INFO_URL});
    var all_infos = {};
    var data = dom.window.document.getElementsByClassName('maintd');
    for (var i = 1; i < data.length; i += 2) {
      all_infos[data[i - 1].textContent.trim()] = data[i].textContent.trim();
    }
    infos.usage = Number(/\d+/.exec(all_infos["使用流量(IPV4)"])[0]);
    infos.balance = Number(/\d+\.\d+/.exec(all_infos["帐户余额"])[0]);
  }());
  // Parse sessions page.
  (function () {
    var ROW_LENGTH = 14;
    infos.sessions = [];
    const dom = new JSDOM(sessions_page, {'url': SESSIONS_URL});
    var data = dom.window.document.getElementsByClassName('maintd');

    for (var i = ROW_LENGTH; i <= data.length - ROW_LENGTH; i += ROW_LENGTH) {
      var session = {
        id: data[i].getElementsByTagName('input')[0].value,
        ip: data[i + 1].textContent.trim(),
        // Date only accept ISO format here.
        start_time: new Date(data[i + 2].textContent.trim().replace(' ', 'T') + '+08:00'),
        usage: utils.parse_usage_str(data[i + 3].textContent.trim()),
        device_name: utils.parse_platform(data[i + 11].textContent.trim())
      };
      infos.sessions.push(session);
      infos.usage += session.usage;
    };

    // Done, return infos.
    console.log('Got info: %s', JSON.stringify(infos));
    callback(null, infos);
  }());
}
