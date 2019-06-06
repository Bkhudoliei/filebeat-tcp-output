package tcpout

import (
	"crypto/tls"
	"fmt"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/outputs"
	"github.com/elastic/beats/libbeat/outputs/codec"
	"github.com/elastic/beats/libbeat/publisher"
	"net"
	//	"time"
)

func init() {
	outputs.RegisterType("tcp", makeUdpout)
}

type tcpOutput struct {
	connection    net.Conn
	connectionTLS *tls.Conn
	address       string
	beat          beat.Info
	observer      outputs.Observer
	codec         codec.Codec
	usessl        bool
	sslconfig     *tls.Config
}

// makeUdpout instantiates a new file output instance.
func makeUdpout(
	beat beat.Info,
	observer outputs.Observer,
	cfg *common.Config,
) (outputs.Group, error) {
	config := defaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return outputs.Fail(err)
	}

	// disable bulk support in publisher pipeline
	err := cfg.SetInt("bulk_max_size", -1, -1)
	if err != nil {
		logp.Warn("cfg.SetInt failed with: %v", err)
	}
	uo := &tcpOutput{
		beat:     beat,
		observer: observer,
	}
	if err := uo.init(beat, config); err != nil {
		return outputs.Fail(err)
	}

	return outputs.Success(-1, 0, uo)
}

func (out *tcpOutput) init(beat beat.Info, c tcpoutConfig) error {

	address := fmt.Sprintf("%s:%d", c.Host, c.Port)
	logp.Info("TCP server address: %v", address)
	out.usessl = c.UseSSL
	out.address = address
	var err error
	if c.UseSSL {
		cert, err := tls.LoadX509KeyPair(c.SSLCert, c.SSLKey)
		if err != nil {
			return err
		}
		out.sslconfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	}

	out.codec, err = codec.CreateEncoder(beat, c.Codec)
	if err != nil {
		return err
	}

	logp.Info("Initialized tcp output. "+
		"Server address=%v", address)

	return nil
}

// Implement Outputer
func (out *tcpOutput) Close() error {
	if out.usessl {
		return out.connectionTLS.Close()
	} else {
		return out.connection.Close()
	}
}

func (out *tcpOutput) Publish(
	batch publisher.Batch,
) error {
	defer batch.ACK()
	var err error
	//Create connection every batch
	if out.usessl {
		out.connectionTLS, err = tls.Dial("tcp4", out.address, out.sslconfig)
		if err != nil {
			return err
		}
	} else {
		out.connection, err = net.Dial("tcp4", out.address)
		if err != nil {
			return err
		}
	}
	defer out.Close()
	st := out.observer
	events := batch.Events()
	st.NewBatch(len(events))

	bulkSize := 0
	dropped := 0
	for i := range events {
		event := &events[i]
		serializedEvent, err := out.codec.Encode(out.beat.Beat, &event.Content)
		if err != nil {
			if event.Guaranteed() {
				logp.Critical("Failed to serialize the event: %v", err)
			} else {
				logp.Warn("Failed to serialize the event: %v", err)
			}
			logp.Debug("tcp", "Failed event: %v", event)

			dropped++
			continue
		}
		if out.usessl {
			_, err = out.connectionTLS.Write([]byte(string(serializedEvent) + "\n"))
		} else {
			_, err = out.connection.Write([]byte(string(serializedEvent) + "\n"))
		}
		if err != nil {
			st.WriteError(err)
			if event.Guaranteed() {
				logp.Critical("Writing event to TCP failed with: %v", err)
			} else {
				logp.Warn("Writing event to TCP failed with: %v", err)
			}
			dropped++
			continue
		}
		bulkSize += len(serializedEvent) + 1
		st.WriteBytes(len(serializedEvent) + 1)
	}

	st.Dropped(dropped)
	st.Acked(len(events) - dropped)
	logp.Warn("Processed events: %v. Dropped events: %v. Bulk size: %v", len(events)-dropped, dropped, bulkSize)
	return nil
}

func (out *tcpOutput) String() string {
	return "TCP(" + out.address + ")"
}
