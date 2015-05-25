import re
import csv
import json
import hashlib
import random
import string

class Cef():
    """ A class to represent a CEF log line """
    def __init__(self, use_salt=True):
        """ A method to initialize stuff """
        # to prevent identical lines from hashing to the same md5
        if use_salt:
            self.salt = salt_generator()
        else:
            self.salt = None

    def parse_line(self, log_line):
        """ A method to parse a single CEF log line """
        # always save the raw line
        self.raw = log_line

        # also calculate the md5 (doen't need to be cryptographically secure) for a uniq id
        m = hashlib.md5()
        if self.salt:
            m.update(self.salt + "||" + self.raw)
        else:
            m.update(self.raw)
        self.md5 = m.hexdigest()

        
        # a CEF event can be sent to us via several formats.
        # Let's save what ever is before the CEF as the header
        parts = log_line.split("CEF:")

        if len(parts) < 2:
            raise Exception(
                    "Invalid log line does not appear to be in CEF format: {0}".format(log_line))
        self.header = parts[0]
        self.raw_cef = parts[1]
        
        # replace \\ with \
        self.raw_cef = self.raw_cef.replace("\\\\", "\\")

        # Split out the CEF fields
        cef_parts = re.split(r'(?<!\\)\|', self.raw_cef)
        if len(cef_parts) > 7:
            self.cef_prefix = cef_parts[:7]
            # remove escape chars
            self.cef_prefix = [s.replace("\\|", "|") for s in self.cef_prefix]

            self.raw_cef_extensions = "|".join(cef_parts[7:])

        else:
            raise Exception("Invalid CEF Prefix. Expected 7 prefix fields and 1 extension field separated by a pipe ('|') char")
        
        if len(self.cef_prefix) == 7:
            self.cef_format_version = self.cef_prefix[0]
            self.vendor = self.cef_prefix[1]
            self.product = self.cef_prefix[2]
            self.version = self.cef_prefix[3]
            self.signature = self.cef_prefix[4]
            self.name = self.cef_prefix[5]
            self.severity = self.cef_prefix[6]
        else:
            raise Exception("Was expecting there to be exactly 7 CEF prefix fields")
        
        # Now extract the extentsions into a dictionary
        self.cef_extensions = extensions2dict(self.raw_cef_extensions)

        return self

    def parse_lines(self, list_of_lines):
        """ A method to parse a list of log lines and return a list of Cef classes """
        return [Cef().parse_line(line) for line in list_of_lines]
            
    def to_dict(self):
        """ Returns a dictionary representation of the CEF line """
        all_fields = self.cef_extensions
        all_fields["cef_format_version"] = self.cef_format_version
        all_fields["raw"] = self.raw
        all_fields["header"] = self.header
        all_fields["vendor"] = self.vendor
        all_fields["product"] = self.product
        all_fields["version"] = self.version
        all_fields["signature"] = self.signature
        all_fields["name"] = self.name
        all_fields["severity"] = self.severity
        if self.salt:
            all_fields["salt"] = self.salt
        all_fields["md5"] = self.md5
        return all_fields
    
    def to_json(self):
        """ Returns a json representation of the CEF line """
        all_fields = {}
        all_fields["cef_format_version"] = self.cef_format_version
        all_fields["raw"] = self.raw
        all_fields["header"] = self.header
        all_fields["vendor"] = self.vendor
        all_fields["product"] = self.product
        all_fields["version"] = self.version
        all_fields["signature"] = self.signature
        all_fields["name"] = self.name
        all_fields["severity"] = self.severity
        meta = {'md5': self.md5}
        if self.salt:
            meta["salt"] = self.salt
        all_fields["extensions"] = self.cef_extensions
        all_fields["info"] = meta
        return json.dumps(all_fields)

    def to_csv_string(self):
        """ Returns two element list. The first element is the headers and the second element is the CSV representation of the CEF line """
        all_fields = self.to_dict()
        headers = sorted(all_fields.keys())
        values = [all_fields[key] for key in all_fields]

        return [",".join(headers), ",".join(values)]

####################################################################
## CEF Utility Methods
####################################################################

def extensions2dict(raw_cef_extensions):
    """ Method to transform CEF extensions into a dictionary of key, value pairs """
    extension_parts = re.split(r'(?<!\\)=', raw_cef_extensions)
 
    cef_extensions = {}

    for i in xrange(len(extension_parts)-1):
        key = extension_parts[i].split(" ")[-1]
        if i+1 == len(extension_parts)-1: # deal with last extention
            value = extension_parts[i+1]
        else:
            value = " ".join(extension_parts[i+1].split(" ")[:-1])
        cef_extensions[key] = value.replace("\\=", "=")

    return cef_extensions

def salt_generator(size=6, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

####################################################################
## Public Methods
####################################################################

def cef2csv(log_line):
    """ A method to convert the CEF format into CSV """
    line = Cef().parse_line(log_line)
    return line.to_csv()


def cef2json(log_line):
    """ A method to convert the CEF format into JSON """
    line = Cef().parse_line(log_line)
    return line.to_json()

def ceflines2csv(list_of_lines):
    """ A method to convert a list of CEF format lines into CSV """
    list_of_cef = [Cef().parse_line(line) for line in list_of_lines]
    all_keys = set()
    for cef in list_of_cef:
        keys = set(cef.to_dict().keys())

        # update the master set
        all_keys |= keys

    header = list(sorted(all_keys))

    csv_lines = [[cef.to_dict().get(k, None) for k in header] for cef in list_of_cef]

    return (header, csv_lines)





####################################################################
## Standalone
####################################################################

if __name__ == "__main__":
    import sys
    import csv

    filenames = []
    if len(sys.argv) > 1:
        filenames = sys.argv[1:]

    # parse all files
    for filename in filenames:
        with open(filename) as f:
            lines = f.read().splitlines()
            header, csv_lines = ceflines2csv(lines)
            with open(filename+"_parsed.csv", "wb") as out:
                w = csv.writer(out)
                w.writerow(header)
                w.writerows(csv_lines)



    
    




















