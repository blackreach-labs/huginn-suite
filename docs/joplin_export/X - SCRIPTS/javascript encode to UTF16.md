---
title: javascript encode to UTF16
updated: 2025-04-18 10:11:55Z
created: 2025-04-18 10:07:07Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

Function can be run from the browsers console:

```
function encode_to_javascript(string) {
			var input = string
			var output = '';
			for(pos = 0; pos < input.length; pos++) {
				output += input.charCodeAt(pos);
				if(pos != (input.length -1)) {
					output += ",";
				}
			}
			return output;
		}
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encode)
```
