const fetch = require("node-fetch");

const rules = require("./rules.json");

async function getCategories() {
    let res = await fetch(env.url + "/api/attack-vector/category", {
        credentials: "include",
        headers: {
            accept: "*/*",
            "accept-language": "en-US,en;q=0.9,vi-VN;q=0.8,vi;q=0.7",
            authorization: env.token,
            "cache-control": "no-cache",
            pragma: "no-cache",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin"
        },
        body: null,
        method: "GET",
        mode: "cors"
    })
        .then(res => res.json())
        .catch(console.error);

    return res.data;
}

async function addRule(rule) {
    console.log("Adding rule: ", rule);
    let res = await fetch(env.url + "/api/admin/one-day-rule", {
        credentials: "include",
        headers: {
            accept: "*/*",
            "accept-language": "en-US,en;q=0.9,vi-VN;q=0.8,vi;q=0.7",
            authorization: env.token,
            "cache-control": "no-cache",
            "content-type": "application/json",
            pragma: "no-cache",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin"
        },
        body: JSON.stringify(rule),
        method: "POST",
        mode: "cors"
    })
        .then(res => res.json())
        .catch(console.error);

    console.log(res);

    if (!res.success) {
        console.log('[+] Failed to add rule, try update rule');

        let ruleId = (
            await fetch(
                env.url + "/api/admin/one-day-rule/" + rule.category_id,
                {
                    credentials: "include",
                    headers: {
                        authorization: env.token,
                        "content-type": "application/json"
                    }
                }
            ).then(res => res.json())
        ).data.find(i => i.rule_id == rule.rule_id).id;

        let res = await fetch(
            env.url + "/api/admin/one-day-rule/" + ruleId,
            {
                credentials: "include",
                headers: {
                    authorization: env.token,
                    "content-type": "application/json"
                },
                body: JSON.stringify({
                    description: rule.description,
                    content_rule: rule.content_rule
                }),
                method: "POST"
            }
        ).then(data => data.json());

        console.log('[+] Update rule done', res);
    }
}

const env = require("./env.js");

(async () => {
    let categories = await getCategories();
    console.log(categories);

    await Promise.all(
        rules.map(rule => {
            let match = rule.content_rule.match(/id:(\d+)/);
            if (!match) {
                console.log("[i] Warning rule failed:", rule);
                return;
            }

            let category = categories.find(cate => cate.name == rule.category);
            if (!category) {
                console.log("[i] Warning category not found:", rule.category);
                return;
            }

            return addRule({
                category_id: categories.find(cate => cate.name == rule.category)
                    .id,
                description: rule.description,
                content_rule: rule.content_rule,
                rule_id: "POL-" + rule.content_rule.match(/id:(\d+)/)[1]
            });
        })
    );
})();
