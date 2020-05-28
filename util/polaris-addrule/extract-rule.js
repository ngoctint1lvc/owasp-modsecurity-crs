const fs = require('fs-jetpack');

function extractRule() {
    let data = fs.read('../../custom-rules/POLARIS-CUSTOM-RULES.conf');
    let rules = [];
    for (let matched of data.matchAll(/# =+\s+(?<category>.*)\s+=+.*\n(?<rules>(.*\n(?!#\s*=+))*)/gm)) {
        let category = matched.groups.category;
        let rulesData = matched.groups.rules;

        // console.log(matched.groups);

        // parse rules
        let description = '';
        let rule = '';
        for (let line of rulesData.split("\n")) {
            if (line.trim().startsWith("#")) {
                if (rule.length > 0) {
                    // end of previous rule
                    rules.push({
                        category: category,
                        description: description,
                        content_rule: rule.replace(/(?<=\W)(block|deny)(?=\s*,)/gm, 'pass')
                    });

                    rule = '';
                    description = '';
                }

                description += line.replace(/^\s*#/, '').trim() + '\n';
                continue;
            }

            // skip empty line
            if (line.trim().length == 0) continue;

            rule += line.trim() + '\n';
        }

        if (rule.length > 0) {
            rules.push({
                category: category,
                description: description,
                content_rule: rule.replace(/(?<=\W)(block|deny)(?=\s*,)/gm, 'pass')
            });
        }
    }

    console.log(rules);

    return rules;
}

let rules = extractRule();
fs.write("./rules.json", rules);