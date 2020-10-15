// Copyright 2020 The klaytn Authors
// This file is part of the klaytn library.
//
// The klaytn library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The klaytn library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the klaytn library. If not, see <http://www.gnu.org/licenses/>.

package kafka

import (
	"crypto/md5"
	"encoding/json"

	"github.com/Shopify/sarama"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/log"
)

var logger = log.NewModuleLogger(log.ChainDataFetcher)

const (
	MsgIdxTotalSegments = iota
	MsgIdxSegmentIdx
	MsgIdxCheckSum
)

const (
	KeyTotalSegments = "totalSegments"
	KeySegmentIdx    = "segmentIdx"
	KeyCheckSum      = "checksum"
)

// Kafka connects to the brokers in an existing kafka cluster.
type Kafka struct {
	config   *KafkaConfig
	producer sarama.SyncProducer
	admin    sarama.ClusterAdmin
}

func NewKafka(conf *KafkaConfig) (*Kafka, error) {
	producer, err := sarama.NewSyncProducer(conf.Brokers, conf.SaramaConfig)
	if err != nil {
		logger.Error("Failed to create a new producer", "brokers", conf.Brokers)
		return nil, err
	}

	admin, err := sarama.NewClusterAdmin(conf.Brokers, conf.SaramaConfig)
	if err != nil {
		logger.Error("Failed to create a new cluster admin", "brokers", conf.Brokers)
		return nil, err
	}

	return &Kafka{
		config:   conf,
		producer: producer,
		admin:    admin,
	}, nil
}

func (k *Kafka) Close() {
	k.producer.Close()
	k.admin.Close()
}

func (k *Kafka) getTopicName(event string) string {
	return k.config.getTopicName(event)
}

func (k *Kafka) CreateTopic(topic string) error {
	return k.admin.CreateTopic(topic, &sarama.TopicDetail{
		NumPartitions:     k.config.Partitions,
		ReplicationFactor: k.config.Replicas,
	}, false)
}

func (k *Kafka) DeleteTopic(topic string) error {
	return k.admin.DeleteTopic(topic)
}

func (k *Kafka) ListTopics() (map[string]sarama.TopicDetail, error) {
	return k.admin.ListTopics()
}

func (k *Kafka) split(data []byte) ([][]byte, int) {
	size := k.config.SegmentSize
	var segments [][]byte
	for len(data) > size {
		segments = append(segments, data[:size])
		data = data[size:]
	}
	segments = append(segments, data)
	return segments, len(segments)
}

func (k *Kafka) makeProducerMessage(topic string, segment []byte, segmentIdx, totalSegments uint64) *sarama.ProducerMessage {
	checkSum := md5.Sum(segment)
	return &sarama.ProducerMessage{
		Topic: topic,
		Headers: []sarama.RecordHeader{
			{
				Key:   []byte(KeyTotalSegments),
				Value: common.Int64ToByteBigEndian(totalSegments),
			},
			{
				Key:   []byte(KeySegmentIdx),
				Value: common.Int64ToByteBigEndian(segmentIdx),
			},
			{
				Key:   []byte(KeyCheckSum),
				Value: checkSum[:],
			},
		},
		Value: sarama.ByteEncoder(segment),
	}
}

func (k *Kafka) Publish(topic string, msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	segments, totalSegments := k.split(data)
	for idx, segment := range segments {
		item := k.makeProducerMessage(topic, segment, uint64(idx), uint64(totalSegments))
		_, _, err = k.producer.SendMessage(item)
		if err != nil {
			logger.Error("sending kafka message is failed", "err", err, "segmentIdx", idx, "segment", string(segment))
			return err
		}
	}

	return err
}
