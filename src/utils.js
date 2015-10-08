exports.time_passed_str = function time_passed_str(t) {
  if (t == null)
    return '从未';

  var delta = Date.now() - t.getTime();

  var minute = 60 * 1000;
  var hour = 60 * minute;
  var day = 24 * hour;

  if (delta < minute)
    return '刚刚';
  else if (delta < hour)
    return (delta / minute).toFixed(0) + '分钟前';
  else if (delta < day)
    return (delta / hour).toFixed(0) + '小时前';
  else
    return (delta / day).toFixed(0) + '天前';
}

exports.usage_str = function usage_str(usage) {
  if (usage == null)
    return '未知';
  else if (usage < 1e3)
    return usage.toString() + 'B';
  else if (usage < 1e6)
    return (usage / 1e3).toFixed(2) + 'K'
  else if (usage < 1e9)
    return (usage / 1e6).toFixed(2) + 'M'
  else
    return (usage / 1e9).toFixed(2) + 'G'
}

exports.balance_str = function balance_str(balance) {
  if (balance == null)
    return '未知';
  else
    return balance.toFixed(2) + '元';
}