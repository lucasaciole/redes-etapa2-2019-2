import pdb
import random
import asyncio
from mytcputils import *

def is_fin_segment(flags):
    return (flags & FLAGS_FIN) == FLAGS_FIN

def is_expected_segment_sent(seq_no, ack_no):
    return seq_no == ack_no

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

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no+1)

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
        self.callback = None
        self.seq_no = random.randint(0, 0xffff)
        self.ack_no = ack_no

        # Start handshake protocol sending SYN+ACK segment to source.
        self.send_synack_segment()


    def send_synack_segment(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        #builds SYN+ACK segment with empty payload
        header  = make_header(dst_port,src_port, self.seq_no, self.ack_no, FLAGS_SYN | FLAGS_ACK)
        segment = fix_checksum(header + b'', src_addr, dst_addr)

        #sends segment through network layer
        self.servidor.rede.enviar(segment, src_addr)

        #updates nextSeqNum expected to receive data
        self.seq_no += 1

    def _retransmission_timer(self, segment, seq_no):
        _, _, dst_addr, _ = self.id_conexao
        print('Timeout for segment of seq_no %i' % seq_no)

        if (seq_no == self.send_base):
            print('Relaying segment with seq_no and ack_no: %i %i' % (seq_no, self.ack_no))
            self.servidor.rede.enviar(segment, dst_addr)
        else:
            print("Won't resend segment with seq_no %i and ack_no %i since it's not the oldest segment" % (seq_no, self.ack_no))

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if is_expected_segment_sent(seq_no, self.ack_no):
            self.ack_no += len(payload)

            if is_fin_segment(flags):
                self.ack_no += 1
                flags = FLAGS_FIN | FLAGS_ACK

            # Send ACK segment to confirm payload reception or fin reception
            if is_fin_segment(flags) or len(payload) > 0:
                resp_header = make_header(src_port, dst_port, self.seq_no, self.ack_no, flags)
                resp_segment = fix_checksum(resp_header + b'', src_addr, dst_addr)
                self.servidor.rede.enviar(resp_segment, src_addr)

            self.callback(self, payload)

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
        # Segmentate data if it's too big for a TCP payload
        segments = self.segmentate_data(dados)

        src_addr, _, _, _ = self.id_conexao

        for segment, seq_num in segments:
            # Send each segment through network layer
            self.servidor.rede.enviar(segment, src_addr)

            # Start retransmission timer for sent segment
            asyncio.get_event_loop().call_later(1.2, self._retransmission_timer, segment, seq_num)


    def segmentate_data(self, data):
        segments = []

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # Check how many times the data is bigger than a TCP payload
        for packet_num in range((len(data)//MSS)):
            # Split payload in multiple segments
            payload = data[packet_num*MSS:(packet_num+1)*MSS]


            # Create segment to given payload chunk
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header + payload, dst_addr, src_addr)

            # Add to created segments lists
            segments.append((segment, self.seq_no))

            # Update next sequence number to be used in a new segment
            self.seq_no += len(payload)

        return segments

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segment = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segment = fix_checksum(segment, dst_addr, src_addr)

        print('Enviando pacote: %i %i' % (self.seq_no, self.ack_no))
        self.servidor.rede.enviar(segment, src_addr)
        pass
