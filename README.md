# ModSecurity Core Rule Set

## Download and install

### Clone this repo and checkout polaris branch

```
git clone https://github.com/ngoctint1lvc/owasp-modsecurity-crs.git
git checkout polaris
```

### Run the WAF

You need to add DVWA local domain in `/etc/hosts` file
```txt
127.0.0.1 dvwa.test   # for dvwa server
```

### Prepare testing tool

Create python3 virtual environment for project and install required packages

```
mkvirtualenv crs-test -p python3
workon crs-test
cd ./tests/regression/
pip install pytest
pip install -r requirements.txt
```

**Note:** python virtualenvwrapper and virtualenv should be installed first.

### Add new rules and testcases

Example rule in `./custom-rules/POLARIS-CUSTOM-RULES.conf`

```bash
# Prevent <!ENTITY something SYSTEM "something" pattern
# Ref: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#exploiting-xxe-to-retrieve-files
SecRule REQUEST_BODY "@rx <!entity\s+[^>]*?\s+system\s+" \
    "id:666666001,\
    phase:2,\
    deny,\
    t:none,t:lowercase,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:removeNulls,\
    msg:'XXE Attack detected by Polaris custom rules',\
    logdata:'Matched Data: XXE data found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-xxe',\
    tag:'polaris-custom-rules'"
```

Example testcase in `./tests/regression/tests/POLARIS-CUSTOM-RULES/000-xxe.yaml`

```yaml
tests:
  - test_title: "XXE Attack 1"
    stages:
      - stage:
          input:
            dest_addr: "127.0.0.1"
            port: 80
            headers:
              Host: "localhost"
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
              Accept-Charset: "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
              Accept-Encoding: "gzip,deflate"
              Accept-Language: "en-us,en;q=0.5"
              Content-Type: "application/x-www-form-urlencoded"
            method: "POST"
            version: "HTTP/1.0"
            data: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n<stockCheck><productId>&xxe;</productId></stockCheck>"
          output:
            log_contains: 'id "666666001"'
```

**Note:**
- Test case for ModSecurity WAF is in `./tests/regression/tests/POLARIS-CUSTOM-RULES/` folder
- Test case for Polaris Lua WAF is in `./tests/regression/tests/POLARIS-WAF-DEV/` folder

## Running

### Running test with ModSecurity WAF
```bash
cd ./tests/regression/
workon crs-test
py.test -v CRS_Tests.py --rule ./tests/POLARIS-CUSTOM-RULES/
```

### Running test with Polaris WAF

Forward log files content of polaris WAF to local `/tmp/log.txt` file
```bash
ssh -t ngoctin@34.73.157.12 docker logs -f proxy --since=0m | grep --line-buffered -P '.*?tin.acbpro.com' > /tmp/log.txt
```

Open other terminal and run test. This tool will check log content in `/tmp/log.txt` to test whether current polaris WAF rule is triggered or not.

Convert testcase from ModSecurity WAF to Polaris WAF. Go to folder of transform-testcase tool.
```bash
cd ./tests/tools/transform-testcase/
```

Run this command once to copy and transform all testcases
```
python transform.py
```

Run this command to transform specific testcases
```
python transform.py ../../regression/polaris-tests/POLARIS-CUSTOM-RULES/*.yaml
```

Output
```
[+] Transform testcase ../../regression/polaris-tests/POLARIS-CUSTOM-RULES/000-xxe.yaml
[+] Transform testcase ../../regression/polaris-tests/POLARIS-CUSTOM-RULES/001-nosqli.yaml
[+] Transform testcase ../../regression/polaris-tests/POLARIS-CUSTOM-RULES/002-template-injection.yaml
[+] Transform testcase ../../regression/polaris-tests/POLARIS-CUSTOM-RULES/test.yaml
```

Transformed testcases will be located in `./tests/regression/polaris-tests/` folder.

```bash
cd ./tests/regression/
workon crs-test
py.test --config waf-lua -v CRS_Tests.py --rule ./polaris-tests/POLARIS-CUSTOM-RULES/
```