import imp
import os
import sys
import cme
from logging import getLogger
from cme.context import Context
from cme.logger import CMEAdapter
from cme.cmeserver import CMEServer

class ModuleLoader:

    def __init__(self, args, db, logger):
        self.args = args
        self.db = db
        self.logger = logger
        self.cme_path = os.path.expanduser('~/.cme')

    def module_is_sane(self, module, module_path):
        module_error = False

        if not hasattr(module, 'name'):
            self.logger.error('{} missing the name variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'description'):
            self.logger.error('{} missing the description variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'options'):
            self.logger.error('{} missing the options function'.format(module_path))
            module_error = True

        elif not hasattr(module, 'on_login') and not (module, 'on_admin_login'):
            self.logger.error('{} missing the on_login/on_admin_login function(s)'.format(module_path))
            module_error = True

        if module_error: return False

        return True

    def load_module(self, module_path):
        module = imp.load_source('payload_module', module_path).CMEModule()
        if self.module_is_sane(module, module_path):
            return module

        return None

    def get_modules(self):
        modules = {}

        modules_paths = [os.path.join(os.path.dirname(cme.__file__), 'modules'), os.path.join(self.cme_path, 'modules')]

        for path in modules_paths:
            for module in os.listdir(path):
                if module[-3:] == '.py' and module != 'example_module.py':
                    module_path = os.path.join(path, module)
                    m = self.load_module(os.path.join(path, module))
                    if m:
                        modules[m.name] = {'path': os.path.join(path, module), 'description': m.description, 'options': m.options.__doc__}

        return modules

    def init_module(self, module_path):

        module  = None
        server  = None
        context = None
        server_port_dict = {'http': 80, 'https': 443}

        module = self.load_module(module_path)

        if module:
            module_logger = CMEAdapter(getLogger('CME'), {'module': module.name.upper()})
            context = Context(self.db, module_logger, self.args)

            module_options = {}

            for option in self.args.module_options:
                key, value = option.split('=', 1)
                module_options[str(key).upper()] = value

            module.options(context, module_options)

            if hasattr(module, 'on_request') or hasattr(module, 'has_response'):

                if hasattr(module, 'required_server'):
                    self.args.server = getattr(module, 'required_server')

                if not self.args.server_port:
                    self.args.server_port = server_port_dict[self.args.server]

                server = CMEServer(module, context, self.logger, self.args.server_host, self.args.server_port, self.args.server)
                server.start()

            return module, context, server
