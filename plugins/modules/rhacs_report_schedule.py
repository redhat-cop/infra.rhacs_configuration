#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024-2026 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_report_schedule
short_description: Manage vulnerability reporting schedules
description:
  - Create, delete, and update vulnerability reporting schedules.
version_added: '1.1.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the vulnerability reporting schedule.
      - Several schedules can have the same name.
      - For a delete operation, the module removes all the schedules matching
        the O(name) parameter.
      - For update operations, the module updates only the configuration that
        matches closely the provided parameters.
    required: true
    type: str
  new_name:
    description:
      - New name for the vulnerability reporting schedule.
      - Setting this option changes the name of the schedule, which current
        name is provided in the O(name) parameter.
      - The module returns an error if the destination schedule already exists.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  description:
    description:
      - Optional description for the vulnerability reporting schedule.
    type: str
  fixability:
    description:
      - Whether to include CVEs that are fixable, not fixable, or both.
      - V(BOTH) by default.
    type: str
    choices:
      - FIXABLE
      - NOT_FIXABLE
      - BOTH
  severities:
    description:
      - Severities of the CVEs to report.
      - V(IMPORTANT) and V(CRITICAL) by default.
    type: list
    elements: str
    choices:
      - UNKNOWN
      - LOW
      - MODERATE
      - IMPORTANT
      - CRITICAL
  image_types:
    description:
      - Whether to include CVEs from deployed images, watched images, or both.
      - V(DEPLOYED) and V(WATCHED) by default.
    type: list
    elements: str
    choices:
      - DEPLOYED
      - WATCHED
  include:
    description: Columns to include in the report.
    type: dict
    suboptions:
      nvd_cvss:
        description:
          - Whether to include the NVD CVSS column in the report configuration.
          - V(true) by default since StackRox and RHACS 4.11.
          - The O(include.nvd_cvss) parameter is deprecated.
            StackRox and RHACS 4.11 and later force the parameter to V(true).
        type: bool
      epss_probability:
        description:
          - Whether to include the EPSS probability column in the report
            configuration.
          - V(true) by default since StackRox and RHACS 4.11.
          - The O(include.epss_probability) parameter is deprecated.
            StackRox and RHACS 4.11 and later force the parameter to V(true).
        type: bool
      advisory:
        description:
          - Whether to include the advisory name and link column in the report
            configuration.
          - V(true) by default since StackRox and RHACS 4.11.
          - The O(include.advisory) parameter is deprecated.
            StackRox and RHACS 4.11 and later force the parameter to V(true).
        type: bool
  since:
    description:
      - Include CVEs based on their discovery date.
      - If O(since=ALL_TIME), then the reports do not exclude CVEs based on
        their date.
      - If O(since=LAST_SENT), then the reports include only the CVEs
        discovered after the last report. When O(since=LAST_SENT), the
        O(email_notifiers) and O(interval) parameters are required.
      - If O(since=DATE), then the reports include the CVEs discovered after
        the date given in the O(date) parameter.
      - V(ALL_TIME) by default.
    type: str
    choices:
      - ALL_TIME
      - LAST_SENT
      - DATE
  date:
    description:
      - The date after which the CVEs must be reported. The O(date) parameter
        is used only when O(since=DATE).
      - The format for the O(date) parameter is C(YYYY-MM-DD), such
        as 2024-05-25.
    type: str
  collection:
    description:
      - Deployment collection to include in the reports.
      - You can specify the collection by its name or by its identifier.
      - See the M(infra.rhacs_configuration.rhacs_collection) module to
        create and manage deployment collections.
      - When you create a schedule, you must provide either the O(collection)
        or the O(entities) parameter.
      - Mutually exclusive with O(entities).
      - Using collections for scoping reports is deprecated since StackRox
        and RHACS 5.0, and will be removed in a future StackRox and RHACS
        release. Use the O(entities) parameter instead.
        StackRox and RHACS do not automatically convert the existing
        collection-based schedules.
    type: str
  entities:
    description:
      - Scope of the reports, defined by rules on the names, the labels, and
        the annotations of clusters, namespaces, and deployments.
      - The reports include the deployments that match all the rules that you
        define. For a given rule, the deployments must match at least one of
        the values that you list.
        For example, if you define a rule for the cluster names and a rule
        for the namespace labels, then the reports include the deployments
        running in the clusters that match one of the cluster names, and in
        the namespaces that have one of the labels.
      - If you set O(entities) to an empty dictionary (V({})), then the
        reports include all the deployments.
      - The module replaces all the existing rules of the schedule with the
        rules that you define in the O(entities) parameter.
      - If you set the O(entities) parameter for a schedule that uses a
        deployment collection, then the module converts the schedule to use
        the O(entities) rules instead of the collection.
      - When you create a schedule, you must provide either the O(collection)
        or the O(entities) parameter.
      - Mutually exclusive with O(collection).
      - The O(entities) parameter requires StackRox and RHACS 4.11 or later.
      - StackRox and RHACS do not support rules on the identifier of the
        clusters, namespaces, or deployments.
    type: dict
    suboptions:
      clusters:
        description:
          - Rules on the clusters.
        type: dict
        suboptions:
          names:
            description:
              - Cluster names.
            type: list
            elements: dict
            suboptions: &rule_values
              value:
                description:
                  - Value to match.
                  - For labels and annotations, the value must use the
                    C(key=value) format, such as V(env=production).
                    When the match type is V(REGEX), the key and the value
                    parts are both regular expressions, such as
                    V(env=prod.*).
                type: str
                required: true
              match_type:
                description:
                  - V(EXACT) for an exact match of the value, or V(REGEX) to
                    use the value as a regular expression.
                  - The StackRox and RHACS web console uses regular
                    expressions.
                type: str
                choices:
                  - EXACT
                  - REGEX
                default: REGEX
          labels:
            description:
              - Cluster labels.
            type: list
            elements: dict
            suboptions: *rule_values
      namespaces:
        description:
          - Rules on the namespaces.
        type: dict
        suboptions:
          names:
            description:
              - Namespace names.
            type: list
            elements: dict
            suboptions: *rule_values
          labels:
            description:
              - Namespace labels.
            type: list
            elements: dict
            suboptions: *rule_values
          annotations:
            description:
              - Namespace annotations.
            type: list
            elements: dict
            suboptions: *rule_values
      deployments:
        description:
          - Rules on the deployments.
        type: dict
        suboptions:
          names:
            description:
              - Deployment names.
            type: list
            elements: dict
            suboptions: *rule_values
          labels:
            description:
              - Deployment labels.
            type: list
            elements: dict
            suboptions: *rule_values
          annotations:
            description:
              - Deployment annotations.
            type: list
            elements: dict
            suboptions: *rule_values
  interval:
    description:
      - Reporting frequency.
      - If you set the O(interval) parameter to V(WEEKLY), then provide
        your chosen week days for the reports in the O(week_days) parameter.
      - If you set the O(interval) parameter to V(MONTHLY), then provide
        your chosen days for the reports in the O(month_days) parameter.
      - When O(interval=UNSET), then the reports are not scheduled.
      - V(UNSET) by default.
    type: str
    choices:
      - UNSET
      - WEEKLY
      - MONTHLY
  week_days:
    description:
      - Name of the days for weekly reports when O(interval=WEEKLY).
      - Mutually exclusive with O(month_days).
      - V([Sunday]) by default.
    type: list
    elements: str
    choices:
      - Monday
      - Tuesday
      - Wednesday
      - Thursday
      - Friday
      - Saturday
      - Sunday
  month_days:
    description:
      - Days of the month for monthly reports when O(interval=MONTHLY).
      - The days in O(month_days) must be between 1 and 31.
      - Mutually exclusive with O(week_days).
      - V([1]) by default.
    type: list
    elements: int
  hour:
    description:
      - Hour in the 24-hour notation at which the report should be created.
      - O(hour) must be between 0 and 23.
      - See the O(minute) parameter to specify the minute in the hour.
      - V(18) by default.
    type: int
  minute:
    description:
      - Minute in the hour at which the report should be created.
      - O(minute) must be between 0 and 59.
      - V(0) by default.
    type: int
  email_notifiers:
    description:
      - Optional email delivery destinations for sending the vulnerability
        reports.
    type: list
    elements: dict
    suboptions:
      notifier:
        description:
          - Name or identifier of the notification method to use for sending
            emails.
          - Only email notification methods can be used.
          - See the M(infra.rhacs_configuration.rhacs_notifier_integration)
            module to create and manage notification methods.
        type: str
        required: true
      to:
        description:
          - Email addresses of the recipients who should receive the
            vulnerability reports.
          - By default, the module uses the recipient email address that the
            notifier method defines.
        type: list
        elements: str
      subject:
        description:
          - Subject line for the emails.
          - If you omit the parameter, then a default subject is used.
        type: str
      body:
        description:
          - Text of the emails.
          - If you omit the parameter, then a default text is used.
        type: str
  state:
    description:
      - If V(absent), then the module deletes all the schedules that match
        the O(name) parameter.
      - The module does not fail if the schedule does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the schedule if it does not
        already exist.
      - If the schedule exists, then the module updates its state, and renames
        the schedule if you provide the O(new_name) parameter.
    type: str
    default: present
    choices: [absent, present]
notes:
  - Although several vulnerability schedules can have the same name,
    you should choose a unique name for each schedule.
  - For update operations, when several schedules have the same name, the
    module selects the schedule that matches most of the provided parameters.
  - Also, the module deletes all the schedules matching the O(name) parameter
    for delete operations.
  - For the schedules that use the O(entities) parameter, StackRox and RHACS
    store the O(severities) and O(fixability) filters in a search query.
    The module also adds the C(Vulnerability State:OBSERVED) filter to that
    query when it creates the schedule, so that the reports exclude the
    deferred and false positive CVEs, as the web console does.
    For updates, the module preserves the additional filters that you might
    have added to the query by using the web console.
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    support: full
    platforms: all
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - infra.rhacs_configuration.auth
"""

EXAMPLES = r"""
- name: Ensure the weekly vulnerability report is scheduled
  infra.rhacs_configuration.rhacs_report_schedule:
    name: Weekly report
    description: Bi-weekly vulnerability report of fixable CVEs
    fixability: FIXABLE
    severities:
      - IMPORTANT
      - CRITICAL
    image_types:
      - DEPLOYED
      - WATCHED
    include:
      nvd_cvss: true
      epss_probability: false
    collection: Sensitive data
    since: DATE
    date: "2024-05-25"
    interval: WEEKLY
    week_days:
      - Sunday
      - Wednesday
    email_notifiers:
      - notifier: email notifications
        to:
          - security@example.com
          - secteam@example.com
        subject: RHACS vulnerability report
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the monthly vulnerability report of the production clusters exists
  infra.rhacs_configuration.rhacs_report_schedule:
    name: Monthly production report
    description: Monthly report of the payment applications in production
    fixability: FIXABLE
    severities:
      - IMPORTANT
      - CRITICAL
    entities:
      clusters:
        names:
          - value: production
            match_type: EXACT
        labels:
          - value: env=prod.*
      namespaces:
        names:
          - value: payments-.*
      deployments:
        annotations:
          - value: team=finance
            match_type: EXACT
          - value: team=accounting
            match_type: EXACT
    interval: MONTHLY
    month_days:
      - 1
      - 15
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the weekly vulnerability report is renamed
  infra.rhacs_configuration.rhacs_report_schedule:
    name: Weekly report
    new_name: Bi-weekly report
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the bi-weekly vulnerability report is removed
  infra.rhacs_configuration.rhacs_report_schedule:
    name: Bi-weekly report
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the vulnerability reporting schedule.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

from datetime import datetime
import copy

from ..module_utils.api_module import APIModule

WEEK_DAYS = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
]


def severity_to_API_type(severity):
    if not severity:
        return None
    if severity == "UNKNOWN":
        return "UNKNOWN_VULNERABILITY_SEVERITY"
    if severity == "LOW":
        return "LOW_VULNERABILITY_SEVERITY"
    if severity == "MODERATE":
        return "MODERATE_VULNERABILITY_SEVERITY"
    if severity == "IMPORTANT":
        return "IMPORTANT_VULNERABILITY_SEVERITY"
    # if severity == "CRITICAL":
    return "CRITICAL_VULNERABILITY_SEVERITY"


# Severities in the order that the web console uses in the search queries
API_SEVERITIES = [
    "CRITICAL_VULNERABILITY_SEVERITY",
    "IMPORTANT_VULNERABILITY_SEVERITY",
    "MODERATE_VULNERABILITY_SEVERITY",
    "LOW_VULNERABILITY_SEVERITY",
    "UNKNOWN_VULNERABILITY_SEVERITY",
]

# Mapping between the `entities' parameter and the API entity scope rules
ENTITY_TYPES = [
    ("clusters", "SCOPE_ENTITY_CLUSTER"),
    ("namespaces", "SCOPE_ENTITY_NAMESPACE"),
    ("deployments", "SCOPE_ENTITY_DEPLOYMENT"),
]
ENTITY_FIELDS = [
    ("names", "FIELD_NAME"),
    ("labels", "FIELD_LABEL"),
    ("annotations", "FIELD_ANNOTATION"),
]

# Search query filter that the web console adds by default to exclude the
# deferred and false positive CVEs
DEFAULT_QUERY_TERMS = ["Vulnerability State:OBSERVED"]


def entities_to_rules(entities):
    """Convert the `entities' parameter to a list of entity scope rules.

    :param entities: The `entities' module parameter.
    :type entities: dict

    :return: The entity scope rules to send to the API.
    :rtype: list
    """
    rules = []
    for param_entity, api_entity in ENTITY_TYPES:
        fields = entities.get(param_entity) or {}
        for param_field, api_field in ENTITY_FIELDS:
            values = fields.get(param_field)
            if not values:
                continue
            rules.append(
                {
                    "entity": api_entity,
                    "field": api_field,
                    "values": [
                        {"value": v["value"], "matchType": v.get("match_type") or "REGEX"}
                        for v in values
                    ],
                }
            )
    return rules


def canonical_rules(rules):
    """Return a representation of entity scope rules that ignores ordering.

    :param rules: Entity scope rules, as returned by the API.
    :type rules: list

    :return: The rules as a set of tuples.
    :rtype: frozenset
    """
    result = set()
    for rule in rules or []:
        values = frozenset(
            (v.get("value", ""), v.get("matchType") or "EXACT")
            for v in rule.get("values") or []
        )
        if values:
            result.add((rule.get("entity"), rule.get("field"), values))
    return frozenset(result)


def parse_query(query):
    """Extract the fixability and the severities from a report search query.

    :param query: The search query, such as
                  ``Severity:CRITICAL_VULNERABILITY_SEVERITY+Fixable:true``
    :type query: str

    :return: A tuple with the fixability (``BOTH``, ``FIXABLE``, or
             ``NOT_FIXABLE``), the set of severities, and the list of the
             other search terms to preserve.
    :rtype: tuple
    """
    fixability = "BOTH"
    severities = set()
    others = []
    for term in (query or "").split("+"):
        if not term.strip():
            continue
        key, sep, values = term.partition(":")
        key_lower = key.strip().lower()
        if sep and key_lower == "severity":
            severities.update(v.strip() for v in values.split(",") if v.strip())
        elif sep and key_lower == "fixable":
            fix_values = set(v.strip().lower() for v in values.split(",") if v.strip())
            if fix_values == set(["true"]):
                fixability = "FIXABLE"
            elif fix_values == set(["false"]):
                fixability = "NOT_FIXABLE"
        else:
            others.append(term)
    return (fixability, severities, others)


def build_query(fixability, severities, others):
    """Build a report search query.

    :param fixability: ``BOTH``, ``FIXABLE``, or ``NOT_FIXABLE``.
    :type fixability: str
    :param severities: The severities to include, in the API format.
    :type severities: set
    :param others: Additional search terms to append to the query.
    :type others: list

    :return: The search query.
    :rtype: str
    """
    terms = []
    if severities:
        sev_list = [s for s in API_SEVERITIES if s in severities]
        sev_list += sorted(s for s in severities if s not in API_SEVERITIES)
        terms.append("Severity:" + ",".join(sev_list))
    if fixability == "FIXABLE":
        terms.append("Fixable:true")
    elif fixability == "NOT_FIXABLE":
        terms.append("Fixable:false")
    terms.extend(others)
    return "+".join(terms)


def get_scope_and_filters(config):
    """Return the scope type and the effective CVE filters of a report.

    For entity-scoped reports, StackRox and RHACS ignore the ``fixability``
    and ``severities`` fields, and use the search query instead. For
    collection-scoped reports, StackRox and RHACS ignore the search query.

    :param config: The report configuration, as returned by the API.
    :type config: dict

    :return: A tuple with the scope type (``entity`` or ``collection``), the
             fixability, the set of severities, and the list of additional
             search terms (always empty for collection-scoped reports).
    :rtype: tuple
    """
    vuln_report = config.get("vulnReportFilters") or {}
    if "entityScope" in (config.get("resourceScope") or {}):
        fixability, severities, others = parse_query(vuln_report.get("query"))
        return ("entity", fixability, severities, others)
    return (
        "collection",
        vuln_report.get("fixability") or "BOTH",
        set(vuln_report.get("severities") or []),
        [],
    )


def main():

    rule_values = dict(
        type="list",
        elements="dict",
        options=dict(
            value=dict(required=True),
            match_type=dict(choices=["EXACT", "REGEX"], default="REGEX"),
        ),
    )

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        description=dict(),
        fixability=dict(choices=["BOTH", "FIXABLE", "NOT_FIXABLE"]),
        severities=dict(
            type="list",
            elements="str",
            choices=["UNKNOWN", "LOW", "MODERATE", "IMPORTANT", "CRITICAL"],
        ),
        image_types=dict(type="list", elements="str", choices=["DEPLOYED", "WATCHED"]),
        include=dict(
            type="dict",
            options=dict(
                nvd_cvss=dict(type="bool"),
                epss_probability=dict(type="bool"),
                advisory=dict(type="bool"),
            ),
        ),
        since=dict(choices=["ALL_TIME", "LAST_SENT", "DATE"]),
        date=dict(),
        collection=dict(),
        entities=dict(
            type="dict",
            options=dict(
                clusters=dict(
                    type="dict",
                    options=dict(names=rule_values, labels=rule_values),
                ),
                namespaces=dict(
                    type="dict",
                    options=dict(
                        names=rule_values, labels=rule_values, annotations=rule_values
                    ),
                ),
                deployments=dict(
                    type="dict",
                    options=dict(
                        names=rule_values, labels=rule_values, annotations=rule_values
                    ),
                ),
            ),
        ),
        interval=dict(choices=["UNSET", "WEEKLY", "MONTHLY"]),
        hour=dict(type="int"),
        minute=dict(type="int"),
        week_days=dict(type="list", elements="str", choices=WEEK_DAYS),
        month_days=dict(type="list", elements="int"),
        email_notifiers=dict(
            type="list",
            elements="dict",
            options=dict(
                notifier=dict(required=True),
                to=dict(type="list", elements="str"),
                subject=dict(),
                body=dict(),
            ),
        ),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(
        argument_spec=argument_spec,
        mutually_exclusive=[("week_days", "month_days"), ("collection", "entities")],
        supports_check_mode=True,
    )

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    description = module.params.get("description")
    fixability = module.params.get("fixability")
    severities = module.params.get("severities")
    image_types = module.params.get("image_types")
    include = module.params.get("include")
    since = module.params.get("since")
    date = module.params.get("date")
    collection = module.params.get("collection")
    entities = module.params.get("entities")
    interval = module.params.get("interval")
    hour = module.params.get("hour")
    minute = module.params.get("minute")
    week_days = module.params.get("week_days")
    month_days = module.params.get("month_days")
    email_notifiers = module.params.get("email_notifiers")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the existing vulnerability reporting schedules
    #
    # GET /v2/reports/configurations
    # {
    #     "reportConfigs": [
    #         {
    #             "id": "66211b6b-fcac-48e8-b583-78943b6862ef",
    #             "name": "myreport",
    #             "description": "my description",
    #             "type": "VULNERABILITY",
    #             "vulnReportFilters": {
    #                 "fixability": "FIXABLE",
    #                 "severities": [
    #                     "CRITICAL_VULNERABILITY_SEVERITY",
    #                     "IMPORTANT_VULNERABILITY_SEVERITY"
    #                 ],
    #                 "imageTypes": [
    #                     "DEPLOYED",
    #                     "WATCHED"
    #                 ],
    #                 "includeNvdCvss": true,
    #                 "includeEpssProbability": false,
    #                 "includeAdvisory": true
    #                 "sinceStartDate": "2024-10-16T00:00:00Z"
    #             },
    #             "schedule": {
    #                 "intervalType": "MONTHLY",
    #                 "hour": 0,
    #                 "minute": 0,
    #                 "daysOfMonth": {
    #                     "days": [
    #                         1
    #                     ]
    #                 }
    #             },
    #             "resourceScope": {
    #                 "collectionScope": {
    #                     "collectionId": "eebb...bb52",
    #                     "collectionName": "mycol"
    #                 }
    #             },
    #             "notifiers": [
    #                 {
    #                     "emailConfig": {
    #                         "notifierId": "657a...74f9",
    #                         "mailingLists": [
    #                             "foo@example.com"
    #                         ],
    #                         "customSubject": "",
    #                         "customBody": ""
    #                     },
    #                     "notifierName": "myemail"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "cdeaff52-e9ae-4b97-9de7-1cf926739166",
    #             "name": "myreport",
    #             "description": "My report",
    #             "type": "VULNERABILITY",
    #             "vulnReportFilters": {
    #                 "fixability": "FIXABLE",
    #                 "severities": [
    #                     "CRITICAL_VULNERABILITY_SEVERITY",
    #                     "IMPORTANT_VULNERABILITY_SEVERITY"
    #                 ],
    #                 "imageTypes": [
    #                     "DEPLOYED",
    #                     "WATCHED"
    #                 ],
    #                 "allVuln": true
    #             },
    #             "schedule": null,
    #             "resourceScope": {
    #                 "collectionScope": {
    #                     "collectionId": "eebb...bb52",
    #                     "collectionName": "mycol"
    #                 }
    #             },
    #             "notifiers": []
    #         }
    #     ]
    # }

    c = module.get_object_path(
        "/v2/reports/configurations", query_params={"pagination.limit": 10000}
    )
    reports = c.get("reportConfigs", [])

    # Retrieve the objects for the given names. Several configurations can
    # have the same name.
    configs = []
    new_configs = []
    for s in reports:
        s_name = s.get("name")
        if name == s_name:
            configs.append(s)
        elif new_name == s_name:
            new_configs.append(s)

    # Remove all the objects matching the given name. For delete operations,
    # the new_name parameter is ignored.
    if state == "absent":
        if not configs:
            module.exit_json(changed=False)
        for config in configs:
            id = config.get("id", "")
            module.delete(
                config,
                "vulnerability reporting schedule",
                "{name} ({id})".format(name=name, id=id),
                "/v2/reports/configurations/{id}".format(id=id),
                auto_exit=False,
            )
        module.exit_json(changed=True)

    # Validate and convert some of the parameters
    if severities:
        req_severities = set([severity_to_API_type(s) for s in severities])
    else:
        req_severities = set()

    if image_types:
        req_image_types = set(image_types)
    else:
        req_image_types = set(["DEPLOYED", "WATCHED"])

    if date:
        try:
            d = datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            module.fail_json(
                msg="the `date' parameter must have the `YYYY-MM-DD' format: {d}".format(
                    d=date
                )
            )
        start_date = d.isoformat() + "Z"
    else:
        start_date = datetime.now().strftime("%Y-%m-%dT00:00:00Z")

    if hour and (hour < 0 or hour > 23):
        module.fail_json(
            msg="the `hour' parameter must be between 0 and 23: {hour}".format(hour=hour)
        )

    if minute and (minute < 0 or minute > 59):
        module.fail_json(
            msg="the `minute' parameter must be between 0 and 59: {minute}".format(
                minute=minute
            )
        )

    if week_days:
        wdays = set([WEEK_DAYS.index(d) for d in week_days])
    else:
        wdays = set([0])

    if month_days:
        mdays = set()
        for d in month_days:
            if d < 1 or d > 31:
                module.fail_json(
                    msg=(
                        "the days in the `month_days' parameter must be "
                        "between 1 and 31: {month_days}"
                    ).format(month_days=", ".join([str(i) for i in month_days]))
                )
            mdays.add(d)
    else:
        mdays = set([1])

    if collection is not None:
        req_collection = module.get_collection(collection)
        if not req_collection:
            module.fail_json(
                msg=(
                    "the deployment collection (in `collection') does not exist: {name}"
                ).format(name=collection)
            )
    else:
        req_collection = None

    if entities is not None:
        req_rules = entities_to_rules(entities)
        req_canonical_rules = canonical_rules(req_rules)
    else:
        req_rules = req_canonical_rules = None

    notifiers = []
    req_notifiers = set()
    if email_notifiers is not None:
        for n in email_notifiers:
            obj = module.get_notifier(n["notifier"])
            if not obj:
                module.fail_json(
                    msg=(
                        "the notifier method (in `email_notifiers') does not exist: {name}"
                    ).format(name=n["notifier"])
                )
            if obj.get("type") != "email":
                module.fail_json(
                    msg=(
                        "the notifier method (in `email_notifiers') is not "
                        "an email notifier: {name}: {t}"
                    ).format(name=n["notifier"], t=obj.get("type"))
                )
            id = obj.get("id")
            notifier_name = obj.get("name")
            subject = n.get("subject") or ""
            body = n.get("body") or ""
            dest = n.get("to") or [obj.get("labelDefault", "")]
            notifiers.append(
                {
                    "emailConfig": {
                        "notifierId": id,
                        "mailingLists": dest,
                        "customSubject": subject,
                        "customBody": body,
                    },
                    "notifierName": notifier_name,
                }
            )
            req_notifiers.add((id, notifier_name, ",".join(sorted(dest)), subject, body))

    # Create the object
    if not configs and not new_configs:
        # Verify that the collection or the entities parameter is provided
        if not collection and entities is None:
            module.fail_json(
                msg="one of the following parameters is required: collection, entities"
            )

        # Build the data to send to the API to create the configuration
        name = new_name if new_name else name
        fixability = fixability if fixability else "BOTH"
        severity_list = (
            list(req_severities)
            if req_severities
            else ["CRITICAL_VULNERABILITY_SEVERITY", "IMPORTANT_VULNERABILITY_SEVERITY"]
        )
        since = since if since else "ALL_TIME"
        interval = interval if interval else "UNSET"
        if since == "LAST_SENT":
            if not notifiers:
                module.fail_json(
                    msg="when `since=LAST_SENT', the `email_notifiers' parameter is required"
                )
            if interval == "UNSET":
                module.fail_json(
                    msg=(
                        "when `since=LAST_SENT', the `interval' parameter is "
                        "required, and cannot be `UNSET'"
                    )
                )

        new_fields = {
            "name": name,
            "description": description if description else "",
            "type": "VULNERABILITY",
            "vulnReportFilters": {
                "fixability": fixability,
                "severities": severity_list,
                "imageTypes": list(req_image_types),
            },
            "notifiers": notifiers,
        }

        if entities is not None:
            # For entity-scoped reports, StackRox and RHACS use the search
            # query instead of the fixability and severities fields
            new_fields["vulnReportFilters"]["fixability"] = "BOTH"
            new_fields["vulnReportFilters"]["severities"] = []
            new_fields["vulnReportFilters"]["query"] = build_query(
                fixability, set(severity_list), DEFAULT_QUERY_TERMS
            )
            new_fields["resourceScope"] = {"entityScope": {"rules": req_rules}}
        else:
            new_fields["resourceScope"] = {
                "collectionScope": {
                    "collectionId": req_collection.get("id", ""),
                    "collectionName": req_collection.get("name", ""),
                }
            }

        if include:
            if include.get("nvd_cvss") is not None:
                new_fields["vulnReportFilters"]["includeNvdCvss"] = include.get("nvd_cvss")
            if include.get("epss_probability") is not None:
                new_fields["vulnReportFilters"]["includeEpssProbability"] = include.get(
                    "epss_probability"
                )
            if include.get("advisory") is not None:
                new_fields["vulnReportFilters"]["includeAdvisory"] = include.get("advisory")

        if since == "ALL_TIME":
            new_fields["vulnReportFilters"]["allVuln"] = True
        elif since == "LAST_SENT":
            new_fields["vulnReportFilters"]["sinceLastSentScheduledReport"] = True
        else:  # since == "DATE"
            new_fields["vulnReportFilters"]["sinceStartDate"] = start_date

        if interval == "UNSET":
            new_fields["schedule"] = None
        else:
            new_fields["schedule"] = {
                "intervalType": interval,
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
            }
            if interval == "WEEKLY":
                new_fields["schedule"]["daysOfWeek"] = {"days": list(wdays)}
            else:  # interval == "MONTHLY":
                new_fields["schedule"]["daysOfMonth"] = {"days": list(mdays)}

        resp = module.create(
            "vulnerability reporting schedule",
            name,
            "/v2/reports/configurations",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    if not configs and new_configs:
        configs = new_configs
        name = new_name
        new_configs = new_name = None

    # A vulnerability reporting schedule with the new name already exists
    if new_configs:
        module.fail_json(
            msg=(
                "the vulnerability reporting schedule (`new_name') already exists: {name}"
            ).format(name=new_name)
        )

    # Verify whether a change is needed. Go through all the configurations
    # that match the given name, and select the one with the most matches.
    min_changes = 100
    for config in configs:
        vuln_report = config.get("vulnReportFilters", {})
        schedule = config.get("schedule")
        schedule = schedule if schedule else {}

        curr_scope, curr_fixability, curr_severities, dummy = get_scope_and_filters(config)
        curr_image_types = set(vuln_report.get("imageTypes", []))
        resource_scope = config.get("resourceScope") or {}

        curr_notifiers = set()
        for n in config.get("notifiers", []):
            email_conf = n.get("emailConfig", {})
            curr_notifiers.add(
                (
                    email_conf.get("notifierId"),
                    n.get("notifierName"),
                    ",".join(sorted(email_conf.get("mailingLists", []))),
                    email_conf.get("customSubject", ""),
                    email_conf.get("customBody", ""),
                )
            )

        curr_wdays = set(schedule.get("daysOfWeek", {}).get("days", []))
        curr_mdays = set(schedule.get("daysOfMonth", {}).get("days", []))

        changes = 0
        if new_name:
            changes += 1
        if description is not None and description != config.get("description"):
            changes += 1
        if fixability and fixability != curr_fixability:
            changes += 1
        if severities and req_severities != curr_severities:
            changes += 1
        if image_types and req_image_types != curr_image_types:
            changes += 1
        if include:
            if include.get("nvd_cvss") is not None and include.get(
                "nvd_cvss"
            ) != vuln_report.get("includeNvdCvss"):
                changes += 1
            if include.get("epss_probability") is not None and include.get(
                "epss_probability"
            ) != vuln_report.get("includeEpssProbability"):
                changes += 1
            if include.get("advisory") is not None and include.get(
                "advisory"
            ) != vuln_report.get("includeAdvisory"):
                changes += 1
        if since == "ALL_TIME" and vuln_report.get("allVuln", False) is False:
            changes += 1
        if (
            since == "LAST_SENT"
            and vuln_report.get("sinceLastSentScheduledReport", False) is False
        ):
            changes += 1
        if (since == "DATE" or (since is None and date is not None)) and (
            not vuln_report.get("sinceStartDate")
            or (
                date is not None
                and start_date[0:10] != vuln_report.get("sinceStartDate")[0:10]
            )
        ):
            changes += 1
        if collection is not None and req_collection.get("id", "") != (
            resource_scope.get("collectionScope") or {}
        ).get("collectionId", ""):
            changes += 1
        if entities is not None and (
            curr_scope != "entity"
            or req_canonical_rules
            != canonical_rules((resource_scope.get("entityScope") or {}).get("rules"))
        ):
            changes += 1
        if interval == "UNSET" and schedule:
            changes += 1
        if (interval == "WEEKLY" or (interval is None and week_days is not None)) and (
            not schedule.get("daysOfWeek") or (week_days is not None and wdays != curr_wdays)
        ):
            changes += 1
        if (interval == "MONTHLY" or (interval is None and month_days is not None)) and (
            not schedule.get("daysOfMonth")
            or (month_days is not None and mdays != curr_mdays)
        ):
            changes += 1
        if hour is not None and hour != schedule.get("hour"):
            changes += 1
        if minute is not None and minute != schedule.get("minute"):
            changes += 1
        if email_notifiers is not None and req_notifiers != curr_notifiers:
            changes += 1

        if changes == 0:
            module.exit_json(changed=False, id=config.get("id", ""))

        if changes < min_changes:
            min_changes = changes
            obj = config

    # Update the configuration
    id = obj.get("id", "")
    name = new_name if new_name else name
    new_fields = copy.deepcopy(obj)
    if new_name:
        new_fields["name"] = new_name
    if description is not None:
        new_fields["description"] = description
    if image_types:
        new_fields["vulnReportFilters"]["imageTypes"] = list(req_image_types)
    if include:
        if include.get("nvd_cvss") is not None:
            new_fields["vulnReportFilters"]["includeNvdCvss"] = include.get("nvd_cvss")
        if include.get("epss_probability") is not None:
            new_fields["vulnReportFilters"]["includeEpssProbability"] = include.get(
                "epss_probability"
            )
        if include.get("advisory") is not None:
            new_fields["vulnReportFilters"]["includeAdvisory"] = include.get("advisory")
    if since == "ALL_TIME":
        new_fields["vulnReportFilters"].pop("sinceLastSentScheduledReport", None)
        new_fields["vulnReportFilters"].pop("sinceStartDate", None)
        new_fields["vulnReportFilters"]["allVuln"] = True
    if since == "LAST_SENT":
        new_fields["vulnReportFilters"].pop("allVuln", None)
        new_fields["vulnReportFilters"].pop("sinceStartDate", None)
        new_fields["vulnReportFilters"]["sinceLastSentScheduledReport"] = True
    if since == "DATE" or (not since and date is not None):
        new_fields["vulnReportFilters"].pop("allVuln", None)
        new_fields["vulnReportFilters"].pop("sinceLastSentScheduledReport", None)
        if "sinceStartDate" not in new_fields["vulnReportFilters"] or date is not None:
            new_fields["vulnReportFilters"]["sinceStartDate"] = start_date

    # Scope of the report and CVE filters. For entity-scoped reports, StackRox
    # and RHACS use the search query instead of the fixability and severities
    # fields. When the scope type changes, the current filters are carried
    # over to the new format.
    curr_scope, curr_fixability, curr_severities, curr_others = get_scope_and_filters(obj)
    req_fixability = fixability if fixability else curr_fixability
    req_sev = req_severities if severities else curr_severities
    if entities is not None:
        new_fields["resourceScope"] = {"entityScope": {"rules": req_rules}}
        req_scope = "entity"
    elif collection is not None:
        new_fields["resourceScope"] = {
            "collectionScope": {
                "collectionId": req_collection.get("id", ""),
                "collectionName": req_collection.get("name", ""),
            }
        }
        req_scope = "collection"
    else:
        req_scope = curr_scope

    if req_scope == "entity":
        # Preserve the additional search terms, such as the ones that users
        # add from the web console
        others = curr_others if curr_scope == "entity" else DEFAULT_QUERY_TERMS
        new_fields["vulnReportFilters"]["fixability"] = "BOTH"
        new_fields["vulnReportFilters"]["severities"] = []
        new_fields["vulnReportFilters"]["query"] = build_query(
            req_fixability, req_sev, others
        )
    else:
        new_fields["vulnReportFilters"]["fixability"] = req_fixability
        new_fields["vulnReportFilters"]["severities"] = list(req_sev)
        if curr_scope == "entity":
            new_fields["vulnReportFilters"]["query"] = ""

    if interval == "UNSET":
        new_fields["schedule"] = None
    if interval == "WEEKLY" or (not interval and week_days is not None):
        if not new_fields["schedule"]:
            new_fields["schedule"] = {
                "intervalType": "WEEKLY",
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
                "daysOfWeek": {"days": list(wdays)},
            }
        else:
            new_fields["schedule"].pop("daysOfMonth", None)
            new_fields["schedule"]["intervalType"] = "WEEKLY"
            if "daysOfWeek" not in new_fields["schedule"] or week_days is not None:
                new_fields["schedule"]["daysOfWeek"] = {"days": list(wdays)}
    if interval == "MONTHLY" or (not interval and month_days is not None):
        if not new_fields["schedule"]:
            new_fields["schedule"] = {
                "intervalType": "MONTHLY",
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
                "daysOfMonth": {"days": list(mdays)},
            }
        else:
            new_fields["schedule"].pop("daysOfWeek", None)
            new_fields["schedule"]["intervalType"] = "MONTHLY"
            if "daysOfMonth" not in new_fields["schedule"] or month_days is not None:
                new_fields["schedule"]["daysOfMonth"] = {"days": list(mdays)}
    if hour is not None and new_fields["schedule"]:
        new_fields["schedule"]["hour"] = hour
    if minute is not None and new_fields["schedule"]:
        new_fields["schedule"]["minute"] = minute
    if email_notifiers is not None:
        new_fields["notifiers"] = notifiers

    module.unconditional_update(
        "vulnerability reporting schedule",
        new_fields["name"],
        "/v2/reports/configurations/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
