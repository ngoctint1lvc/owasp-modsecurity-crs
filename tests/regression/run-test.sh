#!/bin/bash

source ~/.virtualenvs/crs-test/bin/activate
type="$1"
shift

test_pro_all() {
    test_dir="polaris-pro-tests";

    # Kill all background process when using Ctrl+C
    trap 'pkill py.test' INT

    echo "[+] Running new attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/POLARIS-CUSTOM-RULES --output outputs/new-attack.csv &

    echo "[+] Running java attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-944-APPLICATION-ATTACK-JAVA --output outputs/java-attack.csv &

    echo "[+] Running lfi attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-930-APPLICATION-ATTACK-LFI --output outputs/lfi-attack.csv &

    echo "[+] Running rfi attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-931-APPLICATION-ATTACK-RFI --output outputs/rfi-attack.csv &

    echo "[+] Running nodejs attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-934-APPLICATION-ATTACK-NODEJS --output outputs/nodejs-attack.csv &

    echo "[+] Running php attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-933-APPLICATION-ATTACK-PHP --output outputs/php-attack.csv &

    echo "[+] Running rce attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-932-APPLICATION-ATTACK-RCE --output outputs/rce-attack.csv &

    echo "[+] Running xss attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-941-APPLICATION-ATTACK-XSS --output outputs/xss-attack.csv &

    echo "[+] Running sqli attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-942-APPLICATION-ATTACK-SQLI --output outputs/sqli-attack.csv &

    echo "[+] Running protocol attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-921-PROTOCOL-ATTACK --output outputs/protocol-attack.csv &

    jobs

    wait
    echo "[+] Done"
}

test_dev_all() {
    test_dir="polaris-tests";

    set -e

    echo "[+] Running new attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/POLARIS-CUSTOM-RULES --output outputs/new-attack.csv

    echo "[+] Running java attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-944-APPLICATION-ATTACK-JAVA --output outputs/java-attack.csv

    echo "[+] Running lfi attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-930-APPLICATION-ATTACK-LFI --output outputs/lfi-attack.csv

    echo "[+] Running rfi attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-931-APPLICATION-ATTACK-RFI --output outputs/rfi-attack.csv

    echo "[+] Running nodejs attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-934-APPLICATION-ATTACK-NODEJS --output outputs/nodejs-attack.csv

    echo "[+] Running php attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-933-APPLICATION-ATTACK-PHP --output outputs/php-attack.csv

    echo "[+] Running rce attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-932-APPLICATION-ATTACK-RCE --output outputs/rce-attack.csv

    echo "[+] Running xss attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-941-APPLICATION-ATTACK-XSS --output outputs/xss-attack.csv

    echo "[+] Running sqli attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-942-APPLICATION-ATTACK-SQLI --output outputs/sqli-attack.csv

    echo "[+] Running protocol attack testcases"
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule $test_dir/REQUEST-921-PROTOCOL-ATTACK --output outputs/protocol-attack.csv

    echo "[+] Done"
}

test_pro() {
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule polaris-pro-tests/POLARIS-CUSTOM-RULES/ $@
}

test_dev() {
    if [ -z "$1" ]; then
        pattern="polaris-custom-rules";
    else
        pattern="$1";
    fi
    shift;
    py.test --tb=no --config waf-lua CRS_Tests.py -v --rule polaris-tests/*$pattern*/ $@
}

test_local() {
    py.test --tb=no CRS_Tests.py -v --rule tests/POLARIS-CUSTOM-RULES/ $@
}

if [ "$type" = 'pro-all' ]; then
    test_pro_all
elif [ "$type" = 'dev-all' ]; then
    test_dev_all
elif [ "$type" = 'pro' ]; then
    test_pro $@
elif [ "$type" = 'dev' ]; then
    test_dev $@
elif [ "$type" = 'local' ]; then
    test_local $@
fi