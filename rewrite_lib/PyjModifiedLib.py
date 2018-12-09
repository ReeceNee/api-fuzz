try:
    from pyjfuzz.lib import PJFConfiguration
    from pyjfuzz.lib import PJFFactory
    from pyjfuzz.lib import PJFMutators
    from pyjfuzz.lib import PJFBaseException
except ImportError:
    print "[!] Can't find PyJFuzz API library, please install with: 'git clone https://github.com/mseclab/PyJFuzz.git'"
    print "[!] One done install with: 'sudo python setup.py install'"
    exit(-1)

import sys
import urllib
import json
import random
import math

class PJFFactoryPoint(PJFFactory):

    @property
    def fuzzed(self):
        """
        Get a printable fuzzed object
        """
        try:
            if self.config.strong_fuzz:
                fuzzer = PJFMutatorsPoint(self.config)
                if self.config.url_encode:
                    if sys.version_info >= (3, 0):
                        return urllib.parse.quote(fuzzer.fuzz(json.dumps(self.config.json)))
                    else:
                        return urllib.quote(fuzzer.fuzz(json.dumps(self.config.json)))
                else:
                    if type(self.config.json) in [list, dict]:
                        return fuzzer.fuzz(json.dumps(self.config.json))
                    else:
                        return fuzzer.fuzz(self.config.json)
            else:
                if self.config.url_encode:
                    if sys.version_info >= (3, 0):
                        return urllib.parse.quote(self.get_fuzzed(self.config.indent, self.config.utf8))
                    else:
                        return urllib.quote(self.get_fuzzed(self.config.indent, self.config.utf8))
                else:
                    return self.get_fuzzed(self.config.indent, self.config.utf8)
        except Exception as e:
            raise PJFBaseException(e.message if hasattr(e, "message") else str(e))

class PJFMutatorsPoint(PJFMutators):

    def fuzz(self, obj):
        """
        Perform the fuzzing
        """
        json_obj = json.loads(obj)
        params_obj = json_obj["params"]

        def get_fuzzed_buf(obj):
            buf = list(obj)
            FuzzFactor = random.randrange(1, len(buf))
            numwrites=random.randrange(math.ceil((float(len(buf)) / FuzzFactor)))+1
            # print(buf)
            for j in range(numwrites):
                self.random_action(buf)
            return self.safe_unicode(buf)

        def test_json_dumps(buf):
            '''
            test wether buf can be set as a json value
            '''
            test_obj = {}
            test_obj['key'] = buf
            try:
                json.dumps(test_obj)
                return True
            except:
                return False


        fuzzed_parmes = []
        for obj in params_obj:
            str_obj  = str(obj)
            fuzzed_buf = get_fuzzed_buf(str_obj)
            # if fuzzed_buf can't be set as a value of json, then replace it as original one
            if test_json_dumps(fuzzed_buf):
                fuzzed_parmes.append(fuzzed_buf)
            else:
                fuzzed_parmes.append(str_obj)
        json_obj["params"] = fuzzed_parmes
        total_buf = list(json.dumps(json_obj))
        return self.safe_unicode(total_buf)
