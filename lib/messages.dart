import 'dart:convert' show jsonDecode, jsonEncode;

import 'package:decimal/decimal.dart' show Decimal;
import 'package:json_annotation/json_annotation.dart';
import 'package:pointycastle/export.dart' show RSAPrivateKey, RSAPublicKey;

import 'crypto.dart' show RsaKeyHelper;

part 'messages.g.dart';

const MANTA_VERSION = '1.6';
const HASHCODE_K = 37 * 17;

Decimal strToDecimal(String value) => Decimal.parse(value);
String decimalToStr(Decimal value) => value.toString();

abstract class BaseMessage {
  bool _equalData(BaseMessage other) {
    return (jsonEncode(this) == jsonEncode(other));
  }

  @override
  int get hashCode => HASHCODE_K + jsonEncode(this).hashCode;
}

@JsonSerializable()
class MerchantOrderRequestMessage extends BaseMessage {
  @JsonKey(fromJson: strToDecimal, toJson: decimalToStr)
  final Decimal amount;
  final String session_id;
  final String fiat_currency;
  final String crypto_currency;

  const MerchantOrderRequestMessage({
    required this.amount,
    required this.session_id,
    required this.fiat_currency,
    required this.crypto_currency,
  });

  factory MerchantOrderRequestMessage.fromJson(Map<String, dynamic> json) =>
      _$MerchantOrderRequestMessageFromJson(json);

  Map<String, dynamic> toJson() => _$MerchantOrderRequestMessageToJson(this);

  @override
  bool operator ==(Object other) =>
      other is MerchantOrderRequestMessage && _equalData(other);
}

@JsonSerializable()
class AckMessage extends BaseMessage {
  final String txid;
  final String status;
  final String url;

  @JsonKey(fromJson: strToDecimal, toJson: decimalToStr)
  final Decimal amount;

  final String transaction_hash;
  final String transaction_currency;
  final String memo;

  const AckMessage({
    required this.txid,
    required this.status,
    required this.url,
    required this.amount,
    required this.transaction_hash,
    required this.transaction_currency,
    required this.memo,
  });

  factory AckMessage.fromJson(Map<String, dynamic> json) =>
      _$AckMessageFromJson(json);

  Map<String, dynamic> toJson() => _$AckMessageToJson(this);

  @override
  bool operator ==(Object other) => other is AckMessage && _equalData(other);
}

@JsonSerializable()
class Destination extends BaseMessage {
  @JsonKey(fromJson: strToDecimal, toJson: decimalToStr)
  final Decimal amount;

  final String destination_address;
  final String crypto_currency;

  const Destination({
    required this.amount,
    required this.destination_address,
    required this.crypto_currency,
  });

  factory Destination.fromJson(Map<String, dynamic> json) =>
      _$DestinationFromJson(json);

  Map<String, dynamic> toJson() => _$DestinationToJson(this);

  @override
  bool operator ==(Object other) => other is Destination && _equalData(other);
}

@JsonSerializable()
class Merchant extends BaseMessage {
  final String name;
  final String address;

  const Merchant({required this.name, required this.address});

  factory Merchant.fromJson(Map<String, dynamic> json) =>
      _$MerchantFromJson(json);

  Map<String, dynamic> toJson() => _$MerchantToJson(this);

  @override
  bool operator ==(Object other) => other is Merchant && _equalData(other);
}

@JsonSerializable()
class PaymentRequestMessage extends BaseMessage {
  final Merchant merchant;

  @JsonKey(fromJson: strToDecimal, toJson: decimalToStr)
  final Decimal amount;

  final String fiat_currency;
  final List<Destination> destinations;
  final Set<String> supported_cryptos;

  const PaymentRequestMessage({
    required this.merchant,
    required this.amount,
    required this.fiat_currency,
    required this.destinations,
    required this.supported_cryptos,
  });

  factory PaymentRequestMessage.fromJson(Map<String, dynamic> json) =>
      _$PaymentRequestMessageFromJson(json);

  Map<String, dynamic> toJson() => _$PaymentRequestMessageToJson(this);

  PaymentRequestEnvelope getEnvelope(RSAPrivateKey key) {
    final jsonMessage = jsonEncode(this);
    final helper = RsaKeyHelper();
    final signature = helper.sign(jsonMessage, key);

    return PaymentRequestEnvelope(
      message: jsonMessage,
      signature: signature,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is PaymentRequestMessage && _equalData(other);
}

@JsonSerializable()
class PaymentRequestEnvelope extends BaseMessage {
  final String message;
  final String signature;
  final String version;

  const PaymentRequestEnvelope({
    required this.message,
    required this.signature,
    this.version = MANTA_VERSION,
  });

  factory PaymentRequestEnvelope.fromJson(Map<String, dynamic> json) =>
      _$PaymentRequestEnvelopeFromJson(json);

  Map<String, dynamic> toJson() => _$PaymentRequestEnvelopeToJson(this);

  bool verify(RSAPublicKey publicKey) {
    final helper = RsaKeyHelper();
    return helper.verify(signature, message, publicKey);
  }

  PaymentRequestMessage unpack() {
    return PaymentRequestMessage.fromJson(jsonDecode(message));
  }

  @override
  bool operator ==(Object other) =>
      other is PaymentRequestEnvelope && _equalData(other);
}

@JsonSerializable()
class PaymentMessage extends BaseMessage {
  final String crypto_currency;
  final String transaction_hash;
  final String version;

  const PaymentMessage({
    required this.crypto_currency,
    required this.transaction_hash,
    this.version = MANTA_VERSION,
  });

  factory PaymentMessage.fromJson(Map<String, dynamic> json) =>
      _$PaymentMessageFromJson(json);

  Map<String, dynamic> toJson() => _$PaymentMessageToJson(this);

  @override
  bool operator ==(Object other) =>
      other is PaymentMessage && _equalData(other);
}
