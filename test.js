const fs = require("fs");
const path = require("path");
const { hasPathTraversal } = require('./index');

/**
 * This file tests the index main function against the test.txt payload.
 * It will check line by line. Each line represents a possible attack.
 * To run this test just run on this folder $ node test
 */

let errors = 0;

const list = fs
  .readFileSync(path.resolve(__dirname, 'test.txt'))
  .toString('UTF8')
  .split('\n')

list.forEach(item => {
  if (!hasPathTraversal(item)) {
    console.log('SHOULD DENY: ', item);
    errors++;
  }
});

// -------------------------------------------------------

console.log('\n'+'-'.repeat(10)+'\n');
console.log('TESTED: ', list.length);
console.log('FAILED: ', errors);
console.log('SUCCESS: ', list.length - errors);
