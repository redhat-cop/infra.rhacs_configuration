=========================================================================
Red Hat Advanced Cluster Security for Kubernetes Collection Release Notes
=========================================================================

.. contents:: Topics

v2.0.1
======

Release Summary
---------------

Deprecate some options in the ``rhacs_report_schedule`` module.

Minor Changes
-------------

- The ``include.nvd_cvss``, ``include.epss_probability``, and ``include.advisory`` parameters are deprecated because StackRox and RHACS 4.11 and later force the parameters to ``true``.

v2.0.0
======

Release Summary
---------------

Renaming the ``herve4m.rhacs_configuration`` collection to ``infra.rhacs_configuration``, and moving the developments to a new GitHub repository (https://github.com/redhat-cop/infra.rhacs_configuration).

Breaking Changes / Porting Guide
--------------------------------

- The name of the collection changes to ``infra.rhacs_configuration``.

v1.4.1
======

Release Summary
---------------

Fix deprecated Python modules and fix a link checker issue

Minor Changes
-------------

- Change the deprecated ``ansible.module_utils._text`` module to the ``ansible.module_utils.common.text.converters`` module for the ``to_bytes`` and ``to_text`` functions.
- Fix link checker issue with the www.gnu.org link.

v1.4.0
======

Release Summary
---------------

Adding the ``include`` dictionary option to the ``rhacs_report_schedule`` module.

Minor Changes
-------------

- Add the ``include.nvd_cvss``, ``include.epss_probability``, and ``include.advisory`` options to the ``herve4m.rhacs_configuration.rhacs_report_schedule`` module.

v1.3.0
======

New Modules
-----------

- infra.rhacs_configuration.rhacs_image_watch - Manage image watches.
- infra.rhacs_configuration.rhacs_policy - Manage security policies.

v1.2.1
======

Release Summary
---------------

Supporting new StackRox 4.6 features.

Minor Changes
-------------

- Update the ``herve4m.rhacs_configuration.rhacs_external_backup`` module to support S3 compatible storage.
- Update the ``herve4m.rhacs_configuration.rhacs_notifier_integration`` module to support Microsoft Sentinel as a notification method.

v1.1.1
======

Release Summary
---------------

Fixing bugs in the ``herve4m.rhacs_configuration.rhacs_auth_provider`` module.

Bugfixes
--------

- The ``uiEndpoint`` OpenID Connect parameter was wrongly set and prevented authentication.
- Updating a configuration failed because once the authentication provider is used, it cannot be modified. Now, for update operations, the configuration is deleted and then re-created.

v1.1.0
======

New Modules
-----------

- infra.rhacs_configuration.rhacs_compliance_schedule - Manage compliance schedule configurations.
- infra.rhacs_configuration.rhacs_report_schedule - Manage vulnerability reporting schedules.

v1.0.0
======

Release Summary
---------------

Initial public release of the ``herve4m.rhacs_configuration`` collection.
The changelog describes all changes made to the modules and plugins included in this collection.

New Modules
-----------

- infra.rhacs_configuration.rhacs_access_scope - Manage access scopes.
- infra.rhacs_configuration.rhacs_api_token - Create API tokens for accessing the RHACS API.
- infra.rhacs_configuration.rhacs_auth_provider - Manage authentication providers.
- infra.rhacs_configuration.rhacs_cloud_management_platform - Manage RHACS integration with cloud platforms.
- infra.rhacs_configuration.rhacs_collection - Manage deployment collections.
- infra.rhacs_configuration.rhacs_config - Manage RHACS configuration.
- infra.rhacs_configuration.rhacs_delegated_image_scan - Manage delegated image scanning configuration.
- infra.rhacs_configuration.rhacs_exception - Configure vulnerability exception expiration periods.
- infra.rhacs_configuration.rhacs_external_backup - Manage external backup configurations.
- infra.rhacs_configuration.rhacs_group - Manage roles for authentication providers.
- infra.rhacs_configuration.rhacs_image_integration - Manage image vulnerability scanner and registry integrations.
- infra.rhacs_configuration.rhacs_init_bundle - Manage cluster init bundles.
- infra.rhacs_configuration.rhacs_machine_access - Manage machine access configurations.
- infra.rhacs_configuration.rhacs_notifier_integration - Manage notification methods.
- infra.rhacs_configuration.rhacs_permission_set - Manage permission sets.
- infra.rhacs_configuration.rhacs_policy_category - Manage policy categories.
- infra.rhacs_configuration.rhacs_policy_clone - Clone security policies.
- infra.rhacs_configuration.rhacs_policy_export - Export security policies.
- infra.rhacs_configuration.rhacs_policy_import - Import security policies.
- infra.rhacs_configuration.rhacs_policy_notifier - Associate notifiers to policies.
- infra.rhacs_configuration.rhacs_policy_status - Enable or disable policies.
- infra.rhacs_configuration.rhacs_role - Manage roles.
- infra.rhacs_configuration.rhacs_signature - Manage RHACS integrations with Cosign signatures.
