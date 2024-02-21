# Check Path Traversal

Check if a given pathname string contains a possible path traversal attack

## Usage

```js
const { hasPathTraversal } = require('./index.js');

hasPathTraversal('a/b/c'); // false
hasPathTraversal('/../../../../../../../../../../../etc/passwd%00.jpg'); // true
```

## Testing

Just run `node test`. Read the test.js doc string to more info.
