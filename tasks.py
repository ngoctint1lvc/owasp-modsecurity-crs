from invoke import task, run
import os
from util.transform_testcase import transform as transform_testcase


def cd(dir=None):
    working_dir = dir or os.path.abspath(os.path.dirname(__file__))
    os.chdir(working_dir)


cd()

@task
def waf_start(c):
    '''
    Start local ModSecurity WAF for testing
    '''
    print("[+] Starting docker-compose")
    c.run("cd waf && docker-compose up -d")


@task
def update_rule_portal_pro(c):
    '''
    Update new version of custom rules to polaris portal version alpha
    '''
    c.run("cd ./util/polaris-addrule && node extract-rule.js && PRO=1 node addrule.js")


@task
def update_rule_portal_dev(c):
    '''
    Update new version of custom rules to polaris portal version dev
    '''
    c.run("cd ./util/polaris-addrule && node extract-rule.js && node addrule.js")


@task(help={'mode': 'polaris-pro | thesis | polaris-dev | polaris-local'})
def transform(c, mode='polaris-local', domain=None, test='', pattern=''):
    '''
    Transform testcase, need to specify mode
    '''
    if mode == 'polaris-pro':
        transform_testcase(domain or 'verichains.tech', forbiden_check=True, log_check=False, pattern=pattern)
    elif mode == 'thesis':
        transform_testcase(domain or 'nginx.test', forbiden_check=True, log_check=False, remove_normal_tests=True, pattern=pattern)
    elif mode == 'polaris-dev':
        transform_testcase(domain or 'ntsec.cf', forbiden_check=False, log_check=True, pattern=pattern)
    elif mode == 'polaris-local':
        transform_testcase(domain or 'host1.test', forbiden_check=False, log_check=True, pattern=pattern)
    else:
        print("[+] Invalid WAF mode")


@task(help={'mode': 'polaris-pro | thesis | polaris-dev | polaris-local'})
def test(c, mode='polaris-local', test='custom-rules', k=None, all=False, transform_now=False):
    '''
    Test CRS with multiple WAF mode, need to transform for each mode
    '''
    if transform_now:
        transform(c, mode, pattern=test)

    print("[+] Current test mode:", mode)
    cd("./tests/regression")
    if all:
        c.run("./run-test.sh")
    else:
        test = test.upper()
        c.run(f"py.test --tb={'long' if k else 'no'} --config waf-lua CRS_Tests.py -v --rule transformed-tests/*{test}*" + (f" -k '{k}'" if k else ''))


@task
def reload(c):
    '''
    Reload local integrated ModSecurity WAF
    '''
    c.run("cd ./waf && docker-compose exec resty nginx -s reload")


@task(help={"mode": "local dev polaris-local thesis"})
def log(c, mode='local'):
    '''
    Start logging for multiple WAF (local, dev, polaris-local, thesis)
    '''
    if mode == 'polaris-local':
        c.run("docker logs -f --since 1m polaris_proxy_1 &> /tmp/log.txt & tail -f /tmp/log.txt")
    elif mode == 'dev':
        c.run("ssh ngoctin@34.73.157.12 docker logs -f --since=1m proxy | grep --line-buffered 'ntsec.cf' &> /tmp/log.txt & tail -f /tmp/log.txt")
    elif mode == 'local':
        c.run("cd ./waf && docker-compose logs -f --tail 100 resty")
    elif mode == 'thesis':
        c.run(
            "docker logs -f --since 1m openresty-waf &> /tmp/log.txt & tail -f /tmp/log.txt")


@task
def reload_rule_polaris(c):
    '''
    Copy and reload custom rule for local polaris dev WAF
    '''
    rules = "/mnt/shared-data/project/polaris/owasp-modsecurity-crs/rules/REQUEST-903-*.conf"
    polaris_rule_dir = "/mnt/shared-data/project/polaris/polaris/polaris-core/proxy-api/src/core-api/owasp-modsecurity-crs/rules/"
    c.run(f"cp {rules} {polaris_rule_dir}")
    cd(polaris_rule_dir)
    c.run("inv reload-rule")


@task
def request2yaml(c):
    '''
    Allow to convert raw HTTP request to YAML testcase format
    '''
    cd("./util/request2yaml/")
    c.run("code -w -n ./input.txt; python convert.py; code ./output.yaml")
