import imp
import os
import cme


class c2_loader:

    def load_c2(self, c2_path):
        c2 = imp.load_source('c2_method', c2_path)
        return c2

    def get_c2s(self):
        c2s = {}

        c2s_path = os.path.join(os.path.dirname(cme.__file__), 'c2')

        for c2 in os.listdir(c2s_path):
            if c2[-3:] == '.py' and c2[:-3] != '__init__' and c2 != 'c2.py':
                c2_name = c2[:-3]

                c2s[c2_name] = os.path.join(c2s_path, c2)

        return c2s
