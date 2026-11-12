# Dataset CWE Categorization

## Example Format:
### CWE-ID:
- CWE Title;
- What it envolves;

## Memory Management:
### CWE-119: 
- Improper Restriction of Operations within the Bounds of a Memory Buffer;
- This involves accessing memory outside of an allowed memory buffer.

### CWE-362:
- Concurrent Execution using Shared Resource with Improper Synchronization
- This involves race conditions vulnerabilities;

### CWE-416:
- Use After Free
- The product referes memory after it has been freed and can reuse it.

### CWE-476:
- Null Pointer Dereference
- The product dereferences a pointer that it expects to be valid but is NULL.
- This might be only related to languages using memory management like pointers...

### CWE-824:
- Access of Uninitialized Pointer;
- If the pointer contains an uninitialized value, then the value might not point to a valid memory location. This could cause the product to read from or write to unexpected memory locations, leading to a denial of service.

## Input Validation
### CWE-78:
- Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

### CWE-79:
- Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

### CWE-91:
- XML Injection (aka Blind XPath Injection)
- The product does not properly neutralize special elements that are used in XML, allowing attackers to modify the syntax, content, or commands of the XML before it is processed by an end system.

### CWE-94:
- Improper Control of Generation of Code ('Code Injection')
- The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

### CWE-134:
- Use of Externally-Controlled Format String
- The product uses a function that accepts a format string as an argument, but the format string originates from an external source.

### CWE-189:
- Numeric Errors (It is a category - Categories are informal organizational groupings of weaknesses that can help CWE users with data aggregation, navigation, and browsing)
- Weaknesses in this category are related to improper calculation or conversion of numbers.

## Permission
### CWE-255:
- Credentials Management Errors (Category)
- Weaknesses in this category are related to the management of credentials.

### CWE-269:
- Improper Privilege Management
- The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

### CWE-284:
- Improper Access Control
- The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

### CWE-287:
- Improper Authentication
- When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

### CWE-352:
- Cross-Site Request Forgery (CSRF)
- The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.

## Data Protection
### CWE-199:
- Information Management Errors (Category)
- Weaknesses in this category are related to improper handling of sensitive information.

### CWE-200:
- Exposure of Sensitive Information to an Unauthorized Actor
- The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Coding Practices
### CWE-19:
- Data Processing Errors (Category)
- Weaknesses in this category are typically found in functionality that processes data. Data processing is the manipulation of input to retrieve or save information.

### CWE-254:
- 7PK - Security Features (Category)
- Software security is not security software. Here we're concerned with topics like authentication, access control, confidentiality, cryptography, and privilege management.

## Cryptography
### CWE-310:
- Cryptographic Issues
- Weaknesses in this category are related to the design and implementation of data confidentiality and integrity. Frequently these deal with the use of encoding techniques, encryption libraries, and hashing algorithms. The weaknesses in this category could lead to a degradation of the quality data if they are not addressed.

## System Configuration
### CWE-16:
- Configuration (Category)
- Weaknesses in this category are typically introduced during the configuration of the software.

## File Management
### CWE-22:
- Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.

## CWE-59:
- Improper Link Resolution Before File Access ('Link Following')
- The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.