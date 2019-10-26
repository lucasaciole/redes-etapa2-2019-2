import pdb
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
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao # (0 src_addr, 1 src_port, 2 dst_addr, 3 dst_port)
        self.callback = None
        self.seq_no = random.randint(0, 0xffff)
        self.send_base = self.seq_no
        self.ack_no = ack_no
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

        print("Criada conexão com %s usando seq_no %i. ack_no recebido: %i" % (id_conexao[0], self.seq_no, ack_no))

        # Envio do pacote SYN+ACK. HANDSHAKE
        resp_segment = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, FLAGS_SYN + FLAGS_ACK)
        resp_segment = fix_checksum(resp_segment, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(resp_segment, self.id_conexao[0])

        self.seq_no += 1
    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        if((flags & FLAGS_FIN) == FLAGS_FIN): # Flag FIN enviada:
            resp_segment = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, seq_no+1, FLAGS_FIN|FLAGS_ACK) + b''
            resp_segment = fix_checksum(resp_segment, self.id_conexao[0], self.id_conexao[2])

            self.servidor.rede.enviar(resp_segment, self.id_conexao[0])
            self.callback(self, payload)
        elif (seq_no == self.ack_no):
            print('Recebido pacote: %i %i' % (seq_no, ack_no))

            self.ack_no += len(payload)

            resp_segment = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, FLAGS_ACK)
            resp_segment = fix_checksum(resp_segment, self.id_conexao[0], self.id_conexao[2])

            self.servidor.rede.enviar(resp_segment, self.id_conexao[0])

            self.callback(self, payload)
        else:
            print('Recebido pacote: %i %i mas esperava pacote %i %i' % (seq_no, ack_no, self.ack_no, ack_no))

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
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        for packet_num in range((len(dados)//MSS)):
            resp_segment = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_no, self.ack_no, FLAGS_ACK) + dados[packet_num*MSS:(packet_num+1)*MSS]
            resp_segment = fix_checksum(resp_segment, self.id_conexao[0], self.id_conexao[2])

            print('Enviando pacote: %i %i' % (self.seq_no, self.ack_no))
            self.servidor.rede.enviar(resp_segment, self.id_conexao[2])

            self.seq_no += len(dados[packet_num*MSS:(packet_num+1)*MSS])

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        resp_segment = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_no, self.ack_no, FLAGS_FIN)
        resp_segment = fix_checksum(resp_segment, self.id_conexao[0], self.id_conexao[2])

        print('Enviando pacote: %i %i' % (self.seq_no, self.ack_no))
        self.servidor.rede.enviar(resp_segment, self.id_conexao[2])
        pass
