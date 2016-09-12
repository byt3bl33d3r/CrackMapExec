import imp
import os
import sys
import cme
from logging import getLogger
from cme.context import Context
from cme.logger import CMEAdapter
from cme.cmechainserver import CMEChainServer
from cme.moduleloader import ModuleLoader

class ModuleChainLoader(ModuleLoader):

    def __init__(self, args, db, logger):
        ModuleLoader.__init__(self, args, db, logger)

        self.chain_list = []

        #This parses the chain command
        for module in self.args.module_chain.split('=>'):
            if '[' in module:
                module_name = module.split('[')[0]
                module_options = module.split('[')[1][:-1]

                module_dict = {'name': module_name}

                module_dict['options'] = {}
                for option in module_options.split(';;'):
                    key, value = option.split('=', 1)
                    if value[:1] == ('"' or "'") and value[-1:] == ('"' or "'"):
                        value = value[1:-1]
                    
                    module_dict['options'][str(key).upper()] = value

                self.chain_list.append(module_dict)

            else:
                module_dict = {'name': module}
                module_dict['options'] = {}

                self.chain_list.append(module_dict)

    def is_module_chain_sane(self):
        last_module = self.chain_list[-1]['name']

        #Confirm that every chained module (except for the last one) actually supports chaining
        for module in self.chain_list:
            if module['name'] == last_module:
                continue

            module_object = module['object']
            if getattr(module_object, 'chain_support') is not True:
                return False

        return True

    def init_module_chain(self):
        modules = self.get_modules()

        #Initialize all modules specified in the chain command and add the objects to chain_list
        for chained_module in self.chain_list:
            for module in modules:
                if module.lower() == chained_module['name'].lower():
                    chained_module['object'] = self.load_module(modules[module]['path'])

        for module in self.chain_list:
            module_logger = CMEAdapter(getLogger('CME'), {'module': module['name'].upper()})
            context = Context(self.db, module_logger, self.args)

            if module['object'] != self.chain_list[-1]['object']: module['options']['COMMAND'] = 'dont notice me senpai'
            getattr(module['object'], 'options')(context, module['options'])

        if self.is_module_chain_sane():
            server_logger = CMEAdapter(getLogger('CME'), {'module': 'CMESERVER'})
            context = Context(self.db, server_logger, self.args)


            server = CMEChainServer(self.chain_list, context, self.logger, self.args.server_host, self.args.server_port, self.args.server)
            server.start()
            return self.chain_list, server

        return None, None