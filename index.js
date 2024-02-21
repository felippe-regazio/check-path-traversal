const path = require('path');
const { unescape } = require("querystring");

/**
 * Checks if <pathname> contains <limit> consecutive ocurrences of <limit>.
 * 
 * @param {string} pathname pathname to check
 * @param {string} delimiter delimiter to split
 * @param {string} limit max consecutive ocurrences
 *
 * @returns boolean
 */
function hasStrangeConsecutiveSequences(pathname, delimiter, limit) {
  let c = 0;

  const parts = pathname.split(delimiter);

  for(const [index, part] of parts.entries()) {
    if (c === limit - 1) {
      return true;
    }

    if (parts[index+1] === part) {
      c++;
    } else {
      c = 0;
    }
  };

  return false;
}

/**
 * Checks if a pathname string contains a possible path traversal attack.
 * If yes returns true, if nothing detected, false.
 * 
 * @param {string} str the path to check for traversal
 * @param {object} options object options
 * 
 * @returns boolean
 */
function hasPathTraversal(str, options = {}) {
  if (!str || typeof str !== 'string') {
    return false;
  }

  const pathname = str.toLowerCase();
  const pathinfo = path.parse(pathname);

  // By adding a NULL byte, \0, at the end of a string in an HTTP request, 
  // the attacker can bypass the string validation used to sanitize user 
  // input and get access to unauthorized files and directories. 
  if (pathname.indexOf('\0') !== -1) {
    return true;
  }

  // any part of the string cannot be repeated linearly for more than 5 times by default,
  // for example: x/x/x/x/x -> strange x/x/x/x/y/x -> ok
  if ([
    '/',
    '%',
    '\\',
    '..',
    '../',
    '..\\'
  ].some(item => hasStrangeConsecutiveSequences(pathname, item, options.maxConsecutiveSequencies || 5))) {
    return true;
  }

  // prohibited path extensions
  if ([
    '.ini',
    '.asa',
  ].includes(pathinfo.ext)) {
    return true;
  }

  // prohibited path target files
  if ([
    'shadow',
    'passwd',
    'hosts'
  ].some(item => pathinfo.name === item || pathinfo.name.startsWith(`${item}\\\\`))) {
    return true;
  }

  // check for hidden escaped tricks. here we unescape the path
  // recursively till path and unescape(path) being in its normal form
  if (pathname !== unescape(pathname)) {
    return hasPathTraversal(unescape(pathname));
  }

  return false;
}

module.exports = {
  hasPathTraversal
}
