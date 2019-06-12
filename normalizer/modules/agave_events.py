# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import json

from normalizer.modules.basenormalizer import BaseNormalizer


class AgaveEvents(BaseNormalizer):
    channels = ('agave.events',)

    def normalize(self, data, channel, submission_timestamp, ignore_rfc1918=True):
        o_data = self.parse_record_data(data)

        if ignore_rfc1918 and self.is_RFC1918_addr(o_data['SrcIp']):
            return []

        session = {
            'timestamp': submission_timestamp,
            'source_ip': o_data['SrcIp'],
            'source_port': int(o_data['SrcPort']),
            'destination_ip': o_data['DestIp'],
            'destination_port': int(o_data['DestPort']),
            'honeypot': o_data['AgaveApp'],
            'protocol': o_data['Protocol']
        }
        relations = {'session': session}
        return [relations]
