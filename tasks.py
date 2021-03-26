from invoke import task, run
import os
from util.transform_testcase import transform as transform_testcase


def cd(dir=None):
    working_dir = dir or os.path.abspath(os.path.dirname(__file__))
    os.chdir(working_dir)


cd()


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


@task(help={'mode': 'dev | local'})
def transform(c, mode='local', domain=None, test='', pattern=''):
    '''
    Transform testcase, need to specify mode
    '''
    cookies = 'x_polaris_sid=Axoa45kLya/vDTqCXYvaDg4DnY1pvCdv7PVa; x_polaris_cid=Axoa4FyNcImzdYJIeWFa0rLXYHTC2ZPfbQpI; PHPSESSID=v2cu06n9ndqvkbp6dsvp1np8v3; security=impossible'
    if mode == 'dev':
        transform_testcase(domain or 'test.acbpro.com', pattern=pattern, cookies=cookies)
    elif mode == 'local':
        transform_testcase(domain or 'dvwa.test', pattern=pattern, cookies=cookies)
    else:
        print("[+] Invalid WAF mode")


@task(help={'mode': 'dev | local'})
def test(c, mode='local', test='custom-rules', k=None, all=False, transform_now=False):
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
    Reload local Polaris WAF
    '''
    c.run("cd /home/nt/Documents/project/polaris && ./dev.sh compose exec proxy nginx -s reload")


@task
def request2yaml(c):
    '''
    Allow to convert raw HTTP request to YAML testcase format
    '''
    cd("./util/request2yaml/")
    c.run("code -w -n ./input.txt; python3 convert.py; code ./output.yaml")
