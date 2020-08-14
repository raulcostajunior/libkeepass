#include "KeePassFileSettings.h"

using namespace std;


const FormatVersion& KeePassFileSettings::formatVersion() const {
    return _keepassSpecVersion;
}


const FileVersion& KeePassFileSettings::fileVersion() const {
    return _fileVersion;
}


bool KeePassFileSettings::isPayloadCompressed() const {
    return _isPayloadCompressed;
}


const vector<uint8_t>& KeePassFileSettings::masterSeed() const {
    return _masterSeed;
}


const vector<uint8_t>& KeePassFileSettings::encryptionIV() const {
    return _encryptionIV;
}


const vector<uint8_t>& KeePassFileSettings::protectedStreamBytes() const {
    return _protectedStreamBytes;
}


const vector<uint8_t>& KeePassFileSettings::transformSeed() const {
    return _transformSeed;
}


const uint16_t& KeePassFileSettings::transformRounds() const {
    return _transformRounds;
}


const std::vector<uint8_t>& KeePassFileSettings::streamStartBytes() const {
    return _streamStartBytes;
}


const InnerStreamEncryption& KeePassFileSettings::innerRandStreamId() const {
    return _innerRandStreamId;
}
