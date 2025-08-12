import re
import tempfile
import os

class OVPNConfigParser:
    def __init__(self, filepath):
        self.filepath = filepath

    def extract_embedded_blocks(self):
        with open(self.filepath, 'r') as f:
            ovpn_text = f.read()
        blocks = {"ca": None, "cert": None, "key": None}
        for tag in blocks.keys():
            pattern = rf"<{tag}>(.*?)</{tag}>"
            match = re.search(pattern, ovpn_text, re.DOTALL)
            if match:
                content = match.group(1).strip()
                temp_fd, temp_path = tempfile.mkstemp(suffix=f".{tag}.pem")
                with os.fdopen(temp_fd, 'w') as tmp:
                    tmp.write(content)
                blocks[tag] = temp_path
            else:
                raise ValueError(f"Missing <{tag}> block in .ovpn")
        return blocks
