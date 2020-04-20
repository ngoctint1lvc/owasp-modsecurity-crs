const gulp = require('gulp');
const childProcess = require('child_process');

const WAF_RULE_DIR = "./waf/openresty/etc/modsecurity-crs";
const RELOAD_WAF_CMD = "(cd ./waf && docker-compose exec openresty nginx -s reload)";

function reloadCustomRule(cb) {
    childProcess.execSync(`cp -r ./custom-rules ${WAF_RULE_DIR}/ && ${RELOAD_WAF_CMD}`, {
        stdio: 'inherit'
    });
    cb();
}

function reloadCrs(cb) {
    childProcess.execSync(`cp -r ./rules ${WAF_RULE_DIR}/ && ${RELOAD_WAF_CMD}`, {
        stdio: 'inherit'
    });
    cb();
}

function watch() {
    gulp.watch("./custom-rules/*.conf", reloadCustomRule);
    gulp.watch("./rules/*.conf", reloadCrs);
}

exports.default = watch;
exports.reloadCrs = reloadCrs;
exports.reloadRule = reloadCustomRule;