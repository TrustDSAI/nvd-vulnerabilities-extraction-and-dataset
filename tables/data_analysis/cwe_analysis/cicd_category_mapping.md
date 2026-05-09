# CICD Vulnerabilities Category Mapping:

- All information will be presented in descending order, from the most frequent CWE to the least frequent.

# Format example:
## #1 Most used CWE
- If already mapped or not
- CWE Title;
- If not mapped, CWE Description;
- If not mapped, existant category, with a little justification
- If mapped, category

## CWE-79:
- Already mapped.
- Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Input Validation;

## CWE-863:
- Not mapped.
- Incorrect Authorization;
- The product performs an authorization check when an actor attempts to access a resource our perform an action, but it does not correctly perform the check.
- Permission Category. This CWE fails to apply the privilege policy correctly, even though everything else (input, memory, network) was working fine.

## CWE-200:
- Already mapped.
- Exposure of Sensitive Information to an Unauthorized Actor;
- Data Protection;

## CWE-770:
- Not mapped.
- Allocation of Resources Without Limits or Throttling
- The product allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated, in violation of the intended security policy for that actor.
- Coding Practices. If the developer doesn't restrict the resources given to a user, it can lead to a DoS (Denial of Service).

## CWE-862:
- Not mapped.
- Missing Authorization:
- The product does not perform an authorization check when an actor attempts to access a resource or perform an action.
- Permission. This happens when the developer forgets to add a permission check to a particular feature.

## CWE-1333:
- Not mapped.
- Inefficient Regular Expression Complexity
- The product uses a regular expression with a worst-case computational complexity that is inefficient and possibly exponential.
- Coding Practices. When a developer uses a structural complex RegEx, in a way that the evaluator engine takes an exponential time to process some entry strings, leading to a DoS.

## CWE-400:
- Not mapped.
- Uncontrolled Resource Consumption
- The product does not properly control the allocation and maintenance of a limited resource.
- Coding Practices. This is like the main category of CWE-770 and 1333, just as CWE-400 is the general term for all situations where resource consumption gets out of control.

## CWE-918:
- Not mapped.
- Server-Side Request Forgery (SSRF)
- The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.
- Input Validation. With this CWE, the attacker can use the server as an intermediary to attack internal systems that should be protected. All of this via URL.

## CWE-639:
- Not mapped.
- Authorization Bypass Through User-Controlled Key
- The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.
- Permission. This involves gaining unauthorized access to other users' data simply by altering URL parameters or the body of an HTTP request.

## CWE-22:
- Already mapped.
- Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- File Management.

## CWE-352:
- Already Mapped.
- Cross-Site Request Forgery (CSRF).
- Permission.

## CWE-732:
- Not mapped.
- Incorrect Permission Assignment for Critical Resource
- The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- Permission. This usually occurs during installation or file creation, where the software inherits or sets excessively high default permissions (such as global read/write), failing to apply the Principle of Least Privilege.

## CWE-20:
- Not mapped.
- Improper Input Validation
- The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- Input Validation. As the description says, the product receives a input/data but it doesn't validade that the input has the properties that are required to process the data safely.

## CWE-284:
- Already mapped.
- Improper Access Control.
- Permission.

## CWE-601:
- Not mapped.
- URL Redirection to Untrusted Site ('Open Redirect')
- The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.
- Input Validation. The product accepts user input specifying the destination for a redirect. However, it does not validate whether the destination is legitimate or belongs to a list of allowed destinations.

## CWE-287:
- Already mapped.
- Improper Authentication
- Permission

## CWE-532:
- Not mapped.
- Insertion of Sensitive Information into Log File
- The product writes sensitive information to a log file.
- Error Handling and Logging. This compromises data confidentiality, since the records do not have the same level of protection as the production database. As it envolves log files, it goes into this category.

## CWE-94:
- Already mapped.
- Improper Control of Generation of Code ('Code Injection')
- Input Validation.

## CWE-209:
- Not mapped.
- Generation of Error Message Containing Sensitive Information
- The product generates an error message that includes sensitive information about its environment, users, or associated data.
- Error Handling and Logging. This allows the attacker to have some insights in the internal system, leading to some possible main attacks. 

## CWE-269
- Already mapped.
- Improper Privilege Management
- Permission.

## CWE-77
- Not mapped.
- Improper Neutralization of Special Elements used in a Command ('Command Injection')
- The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.
- Input Validation. This can allow the attacker to execute arbitrary commands in the system, potencially assuming total control over the system.

## CWE-264
- Not mapped.
- Permissions, Privileges, and Access Controls (Category)
- Weaknesses in this category are related to the management of permissions, privileges, and other security features that are used to perform access control.
- Permissions. It is a general category that encompasses all failures related to some type of inadequate access control, authentication problems, and privilege management.

## CWE-201:
- Not mapped.
- Insertion of Sensitive Information Into Sent Out Data
- The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.
- Data Protection. This happens when the developer fails to clean up data objects before shipping them, resulting in the exposure of internal data, keys, or private data.

## CWE-502:
- Not mapped.
- Deserialization of Untrusted Data
- The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.
- Input Validation. This implies a failure in validating the provenance of the data, so executing methods during object reconstruction may have some effects on production.

## CWE-116:
- Not mapped
- Improper Encoding or Escaping of Output
- The product prepares a structured message for communication with another component, but encoding or escaping of the data is either missing or done incorrectly. As a result, the intended structure of the message is not preserved.
- Output Encoding. Allows the attacker to introduce control sequences that changes the data interpretation from the receiver component, resulting in injection attacks.

## CWE-1284:
- Not mapped.
- Improper Validation of Specified Quantity in Input
- The product receives input that is expected to specify a quantity (such as size or length), but it does not validate or incorrectly validates that the quantity has the required properties.
- Input validation. If the quantity/value is not well verified, this can lead to memory limits or corruption of business logic.

## CWE-276:
- Not mapped
- Incorrect Default Permissions
- During installation, installed file permissions are set to allow anyone to modify those files.
- Permission. It is very related with CWE-732. During the installation or creation of a resource, default permissions are assigned that allow unauthorized authors access to that resource.

## CWE-306
- Not mapped
- Missing Authentication for Critical Function
- The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.
- Permission. For example, happens when a developer thinks that a URL is secret, however, it does not require any authentication for use, leading it open to attackers.

## CWE-1220
- Not mapped.
- Insufficient Granularity of Access Control
- The product implements access controls via a policy or other feature with the intention to disable or restrict accesses (reads and/or writes) to assets in a system from untrusted agents. However, implemented access controls lack required granularity, which renders the control policy too broad because it allows accesses from unauthorized agents to the security-sensitive assets.
- Permission. Forces users to have broader privileges than necessary to perform their tasks, increasing the blast radius in case of account compromise or operational error

## CWE-312
- Not mapped.
- Cleartext Storage of Sensitive Information
- The product stores sensitive information in cleartext within a resource that might be accessible to another control sphere.
- Data Protection. Exposes the data directly to any actor who gains physical or logical access to the storage medium, eliminating the necessary layer of defense to protect the confidentiality of the information in case of an intrusion.