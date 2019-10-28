import pdb
import time
import math
import random
import asyncio
from mytcputils import *


class Servidor:

    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no + 1)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                self.conexoes.pop(id_conexao)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:

    def __init__(self, servidor, id_conexao, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = random.randint(0, 0xffff)
        self.send_base = self.seq_no
        self.non_acked_data = b''
        self.ack_no = ack_no
        self.timer = None
        self.callback = None

        # attributes used to calc RTT
        self.sent_time = 0
        self.acked_time = 0
        self.is_first_rtt_sampled = True
        self.is_waiting_retransmited_segment = False

        # RTT and timeout interval attributes
        self.timeout_interval = 2
        self.sample_rtt = None
        self.estimated_rtt = None
        self.dev_rtt = None

        # Congestion control attributes
        self.segment_window = 1
        self.data_on_hold = b''
        self.last_sent_seq_no = None

        # Start handshake protocol sending SYN+ACK segment to source.
        self.send_synack_segment()

    def send_synack_segment(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # builds SYN+ACK segment with empty payload
        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_SYN | FLAGS_ACK)
        segment = fix_checksum(header + b'', src_addr, dst_addr)

        # sends segment through network layer
        self.servidor.rede.enviar(segment, src_addr)

        # updates nextSeqNum expected to receive data
        self.seq_no += 1
        self.send_base = self.seq_no

    def __start_timer(self):
        self.__stop_timer()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.__retransmit)

    def __stop_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def __retransmit(self):
        self.timer = None
        self.is_waiting_retransmited_segment = True
        self.segment_window = self.segment_window // 2

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        payload = self.non_acked_data[:min(MSS, len(self.non_acked_data))]

        header = make_header(dst_port, src_port, self.send_base, self.ack_no, FLAGS_ACK)
        segment = fix_checksum(header + payload, dst_addr, src_addr)

        self.servidor.rede.enviar(segment, src_addr)

        self.__start_timer()

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if is_expected_segment_sent(seq_no, self.ack_no):

            if ack_no > self.send_base and (flags & FLAGS_ACK) == FLAGS_ACK:
                self.non_acked_data = self.non_acked_data[ack_no - self.send_base:]
                self.send_base = ack_no

                if self.non_acked_data:
                    self.__start_timer()
                else:
                    self.__stop_timer()
                    if not self.is_waiting_retransmited_segment:
                        self.acked_time = time.time()
                        self.estimate_rtt()

            if self.last_sent_seq_no == ack_no:
                self.segment_window += 1
                self.enviar(self.data_on_hold)

            self.is_waiting_retransmited_segment = False
            self.ack_no += len(payload)

            # Received connection close request
            if is_fin_segment(flags):
                self.ack_no += 1
                flags = FLAGS_FIN | FLAGS_ACK

            # Send ACK segment to confirm payload reception or fin reception
            if is_fin_segment(flags) or len(payload) > 0:
                resp_header = make_header(src_port, dst_port, self.seq_no, self.ack_no, flags)
                resp_segment = fix_checksum(resp_header + b'', src_addr, dst_addr)
                self.servidor.rede.enviar(resp_segment, src_addr)

            self.callback(self, payload)

    def segmentate_data(self, data):
        segments = []

        # Check how many times the data is bigger than a TCP payload
        for packet_num in range((len(data) // MSS)):
            # Split payload in multiple segments
            payload = data[packet_num * MSS: (packet_num + 1) * MSS]

            # Add to created segments lists
            segments.append(payload)

        return segments

    def estimate_rtt(self):
        alfa = 0.125
        beta = 0.25

        if not self.acked_time and self.sent_time:
            return

        self.sample_rtt = self.acked_time - self.sent_time
        print("Sample %.3f = %.3f - %.3f" % (self.sample_rtt, self.acked_time, self.sent_time))

        if self.is_first_rtt_sampled:
            self.is_first_rtt_sampled = not self.is_first_rtt_sampled

            self.estimated_rtt = self.sample_rtt
            self.dev_rtt = self.sample_rtt / 2
        else:
            self.estimated_rtt = (1 - alfa) * self.estimated_rtt + alfa * self.sample_rtt
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(self.sample_rtt - self.estimated_rtt)

        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

        print("New timeout interval: %.3f" % self.timeout_interval)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """

        data_ready = dados[:MSS*self.segment_window]
        self.data_on_hold = dados[MSS*self.segment_window:]
        self.last_sent_seq_no = self.seq_no + len(data_ready)

        # Segmentate data if it's too big for a TCP payload
        segments = self.segmentate_data(data_ready)

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        for payload in segments:
            # Create segment to given payload chunk
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header + payload, dst_addr, src_addr)

            self.non_acked_data += payload

            # Update next sequence number to be used in a new segment
            self.seq_no += len(payload)

            # Send each segment through network layer
            self.servidor.rede.enviar(segment, src_addr)

            # Start retransmission timer for sent segment if not yet started
            if self.timer is None:
                self.sent_time = time.time()
                self.__start_timer()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segment = fix_checksum(header + b'', dst_addr, src_addr)

        self.servidor.rede.enviar(segment, src_addr)


# Utility methods
def is_fin_segment(flags):
    return (flags & FLAGS_FIN) == FLAGS_FIN

def is_expected_segment_sent(seq_no, ack_no):
    return seq_no == ack_no