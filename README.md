# ModSecurity Core Rule Set

## Download and install

### Clone this repo and checkout polaris branch

```
git clone https://github.com/ngoctint1lvc/owasp-modsecurity-crs.git
git checkout polaris
```

### Hot reload rules

Custom rules is located at `./custom-rules` folder. You can add more rules inside this folder. To hot reload newly added rules, modify `gulpfile.js` and run gulp command.

All support gulp tasks

```
[14:10:31] Tasks for /mnt/shared-data/project/owasp-modsecurity-crs/gulpfile.js
[14:10:31] ├── default  // watching rule files and auto reload WAF
[14:10:31] ├── reloadCrs    // force to reload CRS
[14:10:31] └── reloadRule   // force to reload custom rules
```

To begin develop, install and start ModSecurity WAF from https://github.com/ngoctint1lvc/waf.

After running ModSecurity WAF, go to project folder run command
```
yarn
gulp
```

### Prepare testing tool

Create python3 virtual environment for project and install required packages

```
mkvirtualenv crs-test -p python3
workon crs-test
cd ./tests/regression/
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

After saving newly added rules, check if gulp is still running and rules is reload. This is example output
```bash
[14:49:56] Using gulpfile /mnt/shared-data/project/owasp-modsecurity-crs/gulpfile.js
[14:49:56] Starting 'default'...
[14:50:46] Starting 'reloadCustomRule'...
[14:50:48] Finished 'reloadCustomRule' after 1.76 s
```

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
ssh -t ngoctin@34.73.157.12 docker logs -f proxy | grep --line-buffered -P 'ModSecurity DENY(?=.*?tin.acbpro.com)' > /tmp/log.txt
```

Open other terminal and run test. This tool will check log content in `/tmp/log.txt` to test whether current polaris WAF rule is triggered or not.
```bash
cd ./tests/regression/
workon crs-test
py.test --config waf-lua -v CRS_Tests.py --rule ./tests/regression/tests/POLARIS-WAF-DEV/
```

Log file format, and location of log file can be changed in `./tests/regression/config.ini`
```ini
[waf-lua]
log_date_format = %Y/%m/%d %H:%M:%S
log_date_regex = (\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})
log_location_linux = /tmp/log.txt
```

Output of test result can be founed at `./tests/regression/output.csv`.

**Note:** If all rules are failed, maybe you have some problem with network or timezone. Try to change WAF timezone to UTC.