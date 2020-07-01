const core = require('@actions/core')
const btoa = require('btoa')
const glob = require('glob')
const { Toolkit } = require('actions-toolkit')
const fm = require('front-matter')
const nunjucks = require('nunjucks')
const dateFilter = require('nunjucks-date-filter')
const table = require('markdown-table')


function listToArray (list) {
  if (!list) return []
  return Array.isArray(list) ? list : list.split(', ')
}

Toolkit.run(async tools => {
  const template = tools.inputs.filename || '.github/ISSUE_TEMPLATE.md'
  const assignees = tools.inputs.assignees
  // var vulnerabilities = tools.inputs.vulnerabilities || './anchore-reports/vulnerabilities.json'
  const env = nunjucks.configure({ autoescape: false })
  env.addFilter('date', dateFilter)

  const templateVariables = {
    ...tools.context,
    env: process.env,
    date: Date.now()
  }

  let table_data = [["Package", "version", "fix", "vulnerability", "Risk", "Scan_File_Path"]]
  // Read all the scan reports using glob.
  glob.sync("./anchore-reports/scan_*.json")
  .forEach(vulnerabilities => {
      // console.log(vulnerabilities)
      // Get the vulnerability file
      tools.log.debug('Reading vulnerabilities file', vulnerabilities)
      const vulnerability_file_data = tools.getFile(vulnerabilities)
      // const vulnerability_file_data =  fs.readFileSync(vulnerabilities)
      const vulnerabilities_data = JSON.parse(vulnerability_file_data)
      // console.log(Object.keys(vulnerabilities_data))
      // let severities = []
      const issues = vulnerabilities_data.vulnerabilities
      console.log(issues.length)
      issues.forEach((issue, index) => {
        console.log(`vulnerability object row ${index}` )
        // let columns = []
        if (issue.severity === "High"){ //&& issue.fix != "None"){
          // severities.push(issue)
          let vulnerability = `[${issue.vuln}](${issue.url})`
          table_data.push([
            issue.package_name,
            issue.package_version,
            issue.fix,
            vulnerability,
            issue.severity,
            './anchore/dev.json' //vulnerabilities.split("/")[-1]
          ]);
        }
      });
    });
  console.log(table_data)

  // Get the template file
  tools.log.debug('Reading from file', template)
  const file = tools.getFile(template)

  // Grab the front matter as JSON
  const { attributes, body } = fm(file)
  tools.log(`Front matter for ${template} is`, attributes)

  // compose issue body
  const issue_body = body + '\n' + table(table_data)
  tools.log.info(issue_body)

  const templated = {
    body: env.renderString(issue_body, templateVariables),
    title: env.renderString(attributes.title, templateVariables)
  }

  tools.log.debug('Templates compiled', templated)
  tools.log.info(`Creating new issue ${templated.title}`)

  // read open issue created my action
  // @TODO: here
  var createNewIssue = true;
  try {
    const { data: openIssues } = await tools.github.issues.listForRepo({
      ...tools.context.repo,
      creator: 'github-actions[bot]',
      state: 'open'
    });
    tools.log.info(openIssues);

    // Check if issue exists with same vulnerabilities.
    openIssues.forEach(openIssue => {
      if (btoa(openIssue.body) == btoa(templated.body)) {
        createNewIssue = true;
      }
    });

  } catch (err) {
    // Log the error message
    const errorMessage = `Error reading issues`;
    tools.log.error(errorMessage);
    tools.log.error(err);

    // The error might have more details
    if (err.errors) tools.log.error(err.errors);

    // Exit with a failing status
    core.setFailed(errorMessage + '\n\n' + err.message);
    tools.exit.failure();
  }

  // Create the new issue
  if (createNewIssue == true) {
    try {
      const issue = await tools.github.issues.create({
        ...tools.context.repo,
        ...templated,
        assignees: assignees ? listToArray(assignees) : listToArray(attributes.assignees),
        labels: listToArray(attributes.labels),
        milestone: tools.inputs.milestone || attributes.milestone
      })

      core.setOutput('number', String(issue.data.number))
      core.setOutput('url', issue.data.html_url)
      tools.log.success(`Created issue ${issue.data.title}#${issue.data.number}: ${issue.data.html_url}`)
    } catch (err) {
      // Log the error message
      const errorMessage = `An error occurred while creating the issue. This might be caused by a malformed issue title, or a typo in the labels or assignees. Check ${template}!`
      tools.log.error(errorMessage)
      tools.log.error(err)

      // The error might have more details
      if (err.errors) tools.log.error(err.errors)

      // Exit with a failing status
      core.setFailed(errorMessage + '\n\n' + err.message)
      tools.exit.failure()
    }
  }
}, {
  secrets: ['GITHUB_TOKEN']
})
