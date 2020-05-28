from invoke import task, run
import os

def cd(dir=None):
    working_dir = dir or os.path.abspath(os.path.dirname(__file__))
    os.chdir(working_dir)

cd()

@task
def init(c):
    waf_start(c)
    c.run('code .')
    c.run('terminator -l crs', asynchronous=True)

@task
def waf_start(c):
    print("[+] Starting docker-compose")
    c.run("cd waf && docker-compose up -d")

@task
def update_rule_pro(c):
    c.run("cd ./util/polaris-addrule && node extract-rule.js && PRO=1 node addrule.js")

@task
def update_rule_dev(c):
    c.run("cd ./util/polaris-addrule && node extract-rule.js && node addrule.js")

@task
def test(c, k=None):
    print('[+] Truncate local waf logs')
    # clear local waf log
    c.run('echo "" > ./waf/openresty/logs/error.log')
    c.run(f"cd ./tests/regression && ./run-test.sh local" + (f' -k {k}' if k else ''))
        

@task(help={"test": "test filter"})
def test_dev(c, all=False, test='polaris-custom-rules', k=None, transform=False):
    '''
    Test CRS with local polaris waf or polaris dev (need transform -m dev)
    '''
    if transform:
        transform_dev(c, all=True)

    test = test.upper()
    if all:
        c.run(f"cd ./tests/regression && ./run-test.sh dev-all")
    else:
        c.run(f"cd ./tests/regression && ./run-test.sh dev {test}"  + (f' -k {k}' if k else ''))

@task(help={"test": "test filter"})
def test_pro(c, all=False, test='polaris-custom-rules', k=None, transform=False):
    '''
    Test CRS with polaris alpha version
    '''
    if transform:
        transform_pro(c, all=True)

    test = test.upper()
    if all:
        c.run(f"cd ./tests/regression && ./run-test.sh pro-all")
    else:
        c.run(f"cd ./tests/regression && ./run-test.sh pro {test}"  + (f' -k {k}' if k else ''))

@task
def transform_dev(c, host='dvwa.test', all=False):
    '''
    Transform testcase to dev format
    '''
    c.run(f"cd ./util/transform-testcase && HOST={host} python transform.py" + (" all" if all else ""))

@task
def transform_pro(c, host='verichains.tech', all=False):
    '''
    Transform testcase to pro format
    '''
    c.run(f"cd ./util/transform-testcase && HOST={host} PRO=1 python transform.py" + (" all" if all else ""))


@task
def reload(c):
    c.run("cd ./waf && docker-compose exec resty nginx -s reload")

@task(help={"mode": "local dev polaris"})
def log(c, mode='local'):
    if mode == 'polaris':
        c.run("docker logs -f --since 1m polaris_proxy_1 &> /tmp/log.txt & tail -f /tmp/log.txt")
    elif mode == 'dev':
        c.run("ssh-polaris-edge docker logs -f --since=1m proxy &> /tmp/log.txt & tail -f /tmp/log.txt")
    else:
        c.run("cd ./waf && docker-compose logs -f --tail 100 resty")

@task
def reload_rule(c):
    custom_rules = "/mnt/shared-data/project/polaris/owasp-modsecurity-crs/custom-rules/POLARIS-CUSTOM-RULES.conf"
    polaris_rule_dir = "/mnt/shared-data/project/polaris/polaris/polaris-core/proxy-api/src/core-api/owasp-modsecurity-crs/rules/"
    c.run(f"cp {custom_rules} {polaris_rule_dir}")
    cd(polaris_rule_dir)
    c.run("inv reload-rule")