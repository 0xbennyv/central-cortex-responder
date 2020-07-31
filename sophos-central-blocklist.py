#!/usr/bin/python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests
import central_oauth

class SoarConnector(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.sophos_central_tenant_secret = self.get_param('config.sophos_central_tenant_secret', None, 'No Secret Set')
        self.sophos_central_tenant_clientid = self.get_param('config.sophos_central_tenant_clientid', None, 'No ID set')
        self.observable = self.get_param('data.data', None, 'Data is empty')
        self.observable_type = self.get_param('data.dataType', None, 'Data type is empty')
        self.title = self.get_param("data.case.title", None, "title is missing")

        self.jwt, self.tenant_id, self.tenant_type, self.data_region = central_oauth.Authenticate.auth(self.sophos_central_tenant_clientid, \
                                                                                    self.sophos_central_tenant_secret)

    def run(self):
        Responder.run(self)
        if self.observable_type == 'hash':
            u = f'{self.data_region}/endpoint/v1/settings/blocked-items'
            
            b = {'type': 'sha256','properties': 
                    {
                    'sha256': f'{self.observable}'
                    },
                    'comment': f'Submitted by Cortex - Case:{self.title}'
                }
            h = {'Authorization': f'Bearer {self.jwt}',
                'X-Tenant-ID': f'{self.tenant_id}'
                }

            r = requests.post(u, headers=h, json=b)
            
            self.report({'message': f'Successfully blocked in SOPHOS Central'})

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='Blocked on all SOPHOS Endpoints')]


if __name__ == '__main__':
    SoarConnector().run()
