## How to run

Convert rule to json format
```
node extract-rule.js
```

Create environment file `env.js`
```js
const envs = {
    "dev": {
        url: "<url>",
        token: "<token>"
    }
};

module.exports = envs['dev'];
```

Import to polaris
```
node addrule.js
```