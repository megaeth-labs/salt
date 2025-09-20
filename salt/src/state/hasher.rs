//! Hashing utilities for mapping plain keys to bucket locations.
//!
//! This module provides deterministic hash functions to:
//! - Map plain keys (e.g., account addresses, storage keys) to bucket IDs
//! - Generate probe sequences for slot allocation within buckets
//!
//! All functions use AHash with fixed seeds to ensure deterministic results.

use super::ahash::fallback::RandomState;
use crate::constant::NUM_META_BUCKETS;
use crate::types::BucketId;
use std::hash::{BuildHasher, Hasher};

/// Fixed seeds derived from the lower 32 bytes of keccak256("Make Ethereum Great Again").
const HASHER_SEEDS: [u64; 4] = [0x921321f4, 0x2ccb667e, 0x60d68842, 0x077ada9d];

/// Computes a deterministic 64-bit hash of the input bytes.
#[inline(always)]
fn hash(bytes: &[u8]) -> u64 {
    static HASH_BUILDER: RandomState = RandomState::with_seeds(
        HASHER_SEEDS[0],
        HASHER_SEEDS[1],
        HASHER_SEEDS[2],
        HASHER_SEEDS[3],
    );

    let mut hasher = HASH_BUILDER.build_hasher();
    hasher.write(bytes);
    hasher.finish()
}

/// Determines which bucket a plain key belongs to.
///
/// Returns a bucket ID in the range [NUM_META_BUCKETS, NUM_BUCKETS).
/// The first NUM_META_BUCKETS buckets are reserved for metadata storage.
#[cfg(not(feature = "test-bucket-resize"))]
#[inline(always)]
pub fn bucket_id(key: &[u8]) -> BucketId {
    use crate::constant::NUM_KV_BUCKETS;
    (hash(key) % NUM_KV_BUCKETS as u64 + NUM_META_BUCKETS as u64) as BucketId
}

/// Determines which bucket a plain key belongs to.
///
/// When the `test-bucket-resize` feature is enabled, this function maps
/// keys into a smaller number of buckets for testing purposes. The number of
/// buckets can be controlled via the `NUM_DATA_BUCKETS` environment variable.
#[cfg(feature = "test-bucket-resize")]
#[inline(always)]
pub fn bucket_id(key: &[u8]) -> BucketId {
    let num_buckets = std::env::var("NUM_DATA_BUCKETS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    (hash(key) % num_buckets + NUM_META_BUCKETS as u64) as BucketId
}

/// Hashes a plain key with a nonce to generate probe sequences.
///
/// This is used to determine slot positions within a bucket during
/// insertion, lookup, and deletion operations.
#[inline(always)]
pub fn hash_with_nonce(plain_key: &[u8], nonce: u32) -> u64 {
    // Optimize for common case: avoid heap allocation for typical key sizes
    const STACK_BUFFER_SIZE: usize = 64;

    let key_len = plain_key.len();
    if key_len + 4 <= STACK_BUFFER_SIZE {
        let mut buffer = [0u8; STACK_BUFFER_SIZE];
        buffer[..key_len].copy_from_slice(plain_key);
        buffer[key_len..key_len + 4].copy_from_slice(&nonce.to_le_bytes());
        hash(&buffer[..key_len + 4])
    } else {
        // Fallback for unusually large keys
        let mut data = plain_key.to_vec();
        data.extend_from_slice(&nonce.to_le_bytes());
        hash(&data)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::constant::NUM_KV_BUCKETS;

    /// Test data: 260 20-byte keys that all hash to the same bucket.
    /// These are Ethereum address-like values specifically chosen to collide in bucket assignment.
    /// This data is useful for testing bucket capacity expansion and hash table behavior under load.
    pub const SAME_BUCKET_TEST_KEYS: &[&str] = &[
        "e1f65916535230d5abcc5d022348fced0ebcbd16",
        "bd2369b04dd7db579559851609fb9d47c4c64895",
        "1efa3d6eef22ed3971c3ad2c06743880fe147bda",
        "78fb562691afd9adf22cf8d6c2c615c366905409",
        "13887c502be115287121f245f0093db41f9f101a",
        "b043e57ec98f407f18b668a7ac10f83bedab0f27",
        "770721e247aa2e506410fbcaf7ab53ad07d970c5",
        "284fb7bf01259d2138cc3a81611bb20b09614a34",
        "69e861f856635f4bca286c869a81e9cfc799e2df",
        "0f020303e4ffa83cd20f77804f9e66ba8b928973",
        "a76c9c3d6d474c6ea31e8d9346030ad6b36d7e8c",
        "504a5b7d743c67906a62d5c2d05533e9ae72730d",
        "31aebbd3ed3eb24f6871bcfbc290cec16718531b",
        "94e13a9fcaaa53f00e7e0b305679e1e4fbba445a",
        "24c86f115e5977f945083c8412b84467bce6582a",
        "db9c6824ca1e7fd3ce7ea6b76e142b00eb276e86",
        "5e86a0d73196db70ce5ffc1594fc8aa34683940c",
        "d9f0048750d657628169eac0e2b590008fb5b41f",
        "61cbff572f4fbecfb2a23433df9379ac80c8e4f7",
        "804ebecf4f930839c0588af6f8e4806ca22d472a",
        "1969f584ad7326a5e4261bc69b1d4028e9755fb7",
        "6d35371e7d35c863813a1b76cc451775f8c56a63",
        "e7f1d9533a632df4e3fe45f8d60cd38bc9801702",
        "0225e9090fc4e52fe6596d4580cebe604eb1f7f2",
        "8424dc1036b8a0df2b00829afcb859194804b073",
        "a133dc051bddb7bc523323cfe32b9911b27b45c5",
        "867f498dc1dbc74d296b73247e6afd54e4f6272c",
        "175461365f3c1d5078ec7c46709c9bb3d254a157",
        "fafb30960467dda483532daf3e8c96feff5bbf78",
        "84aae69cf289f649e57d9bd16b6c800389917dd5",
        "2490e7724a132530040a38dab9a7276f46aabb7f",
        "3e0629e2eefe49497c8a0ad304292493dd653eeb",
        "cf68411e5f5e320252469db076eb8b63977fe843",
        "6e1367ff77e9ee2c56d0c8e36761772fdadd2445",
        "ab5902583830b67b2c2826a73fdbe4baee17e101",
        "7989fd14da779f888933e05c48e2d00726759d6e",
        "424946ef5cf40e13bec0ae899fd2027e41c0756b",
        "a9a52ccfda068097f4074badd3455acccfd01fd9",
        "3a5173bbc3cf41abb95764db4339ec5c932fc619",
        "494f159f1440fdf61ef8d3e6ecb1e6c88db51c7a",
        "58875044163c08a6559c45bad86a26e0150885bf",
        "67ae34b933ff64fb79eb0b8d87621a0a46d03cbe",
        "b8c0405d4f3cbab2d7568e1c0111ea075485d664",
        "fbd345fc288be7c88fb29bf6e51446d991ae109f",
        "81423fe75a836091b165dca1e4d9ca611196bf00",
        "c66f27ed67930cfeb8a31ab481de893faad9bea0",
        "8e7e29672947574dadb5c2657d6c7ce5d3f2d173",
        "d4e3efadd21f134939b01882162296e47d689159",
        "b331070db53f06ef2be992a7a3fe11403f10ccfa",
        "f798cd0abdbb912ff7846bc74a8dc6dd50cb495d",
        "f0e4cf9f741a7d4dd8519cd8ef27c2002eac9346",
        "f87c850ee516323f381ab001ba97e0710e004e86",
        "116b8801f6de50732b311afe42dbf4936d28b44f",
        "3a5fd9ad896b0165bb0da5bfd571d91d56b6e578",
        "348f8581bb4e5c82623a29dace59317f6dc84916",
        "d44d2d9435ca46f5658ada25c42a2c46f5140a9d",
        "39ba7adfd4138b38c78db114992041d3e00149cf",
        "8fc8233781b1c91a25c75263cc9586bb0441f7d7",
        "472b06e228faa54b44d435aa2f8469fbf9826dff",
        "4d5b85570d5efe455df6ced9df837415e202848e",
        "1683ef6ea6be17cf931c8a011bba63323537daea",
        "a6a9a4365c3917d76f4c1efa7eef6ff9f4f916f6",
        "569d7e6bf232445fc50b12d8a9cedd761393cb41",
        "47c357b168a55c419eb5e9ff1e14ecf95f159f23",
        "6ff316145834857a4b4fc4257830ff7a2f8ad5b1",
        "da368d50721a5664844aabf331b748dcc1f9c710",
        "52dd5243167661da2ae364ecf514e7f5032855de",
        "ac40c5802776ec4cc4d1900e4a1d401a6f5664a4",
        "5666f6256e4d61f8bdbf935dbbca156a6c1dad80",
        "dcc54080b585d9a93ed9b9e0b9e9c4a85405a022",
        "903036e0cc93cf84cb4af40ffd28047d1f881791",
        "75039bc826a91bbeb6035efb36c2d965f5dd983a",
        "55c8323675118a715df66188be458b6d7e3957fc",
        "d21bb8fb595c4b2d243221776bd4cb393554c2b3",
        "5f943a9aa5c9c8bcc3f433e6591cdebce3022a58",
        "182bcc4ff7d450a4929b5e04b8949bb3fe6cf151",
        "1f96b56e2e780568ef938e2478a9ea9305d8288f",
        "b40d6af96e4b237ae72b87827c79e5e63e28e33e",
        "1acb45a676f303a1c046e70ae3c556fc17b2bfff",
        "4ff1f8c58358f57f71b3aa0abc60f82364f4f354",
        "ca84b4748261ca963fb7ea65351d52a60ecb7209",
        "be12fed226d5c855021871de32c063a1cb8859ae",
        "c26d891c4095b2137a331d2deec9dbc82239dbf5",
        "547e960b68fa8493bf9b6c87f5cdbef96a695af7",
        "59b00b3cffdf786cf0fe1549b267dbd9dcf9e1fd",
        "9e30284877ff1999c32b408e17cb52f276f45e51",
        "d0248f83fc2e2a62b823e5fe61da586d977cad97",
        "68fcd6e4de75f818cfd38fc8dfeb27508889b2cc",
        "574e0c6c23b125e14d97e130faf61187de29dd10",
        "51fbc8cf485b8fbae0c45edad879356d84cf5a6a",
        "2b4d57d6e169c2ecc5cd6c0789f0cd60f68a0039",
        "20456c58f25199fc770db6742b91e698ac73da85",
        "8baa869a14f6899fa1c645958e76f38b3e32c972",
        "9344bfb1d1d3f7623a0f4e0d80ac05fd5cfa94c0",
        "fa642ab320349447cba3c2027872eacb092bea94",
        "1f94e9e1f0efaf37e8aa122a04b5ffcecc6b6393",
        "ceabed24f8b5fbf3cbc245019592793e76b4cb07",
        "823b496bfe4695b1440710090627a6f27500324e",
        "2e76c918b2ee11ed434e7fd295dba0088f7abd6f",
        "959d5af44d074b408fb23111bb7994b4c47596a1",
        "f917e957ddba2331c4a44f754973be53d7796f9c",
        "c2fdbade893721f8b2a5cecde0d9503d5d8890f4",
        "8af54d7a62e232a2bc073adcb201cf17cf95cba3",
        "48385303ed8015d73469b14c0b987b323699c434",
        "a2787466a220129145df73845cdd868ef7dd0314",
        "b1a92179b1f741307601af2a06cd898fe717895b",
        "38d05b540911bb73279e71a8acc2f3c73190bb3c",
        "e206af14c6601ba7a3d4743b38a16afe33b54b4c",
        "3d6cebe3ea4101b5790c7dddbea7ac0ea14babdb",
        "6236a0fa2afd24249b404bf89410299c4838e5c6",
        "15ea7048eae0aba4812c39bee42b73d6f53b5a6e",
        "b70c9d3e19896532ca3f25b4122a5d0dfa2721df",
        "df50a31e4396ece15ace561bfe5126d44bf1a910",
        "431f76943566882d753964cbec651c57fcb7559f",
        "f90213684110db1502eeb9220f960a0780596e72",
        "8472c8be85a8bf1f9e65e662bb71c2a8e34d4326",
        "be719168ad97183ea6e3a9b3c079483de2d395f4",
        "0969afed05fdb678f09ee517fe8ca22154af5780",
        "392fa334a99560a717a7d25ed7417e530a2f1851",
        "4f0b3a84f9d68d5db228baed5acd250da3638cd6",
        "194a6fc974bc69ab8ff94b041dadb99292010d91",
        "05c748eaf5b8c8e5d9d955b863a96a68ed3c35e7",
        "c92fe28f145ff3073d6006978d76ebeec8e54e67",
        "1b93e980386e45e36256db6f9f3f0ecfa99f7c34",
        "06b7e8d43668887121e9da08143b8c1ce2e7c942",
        "334e794296624a4ce8294dd57e191abac27767e1",
        "2156e5056d40e4e338abb9fa0bc838e2a28b3777",
        "364bbba8b90868c37616896191b0e75331009c65",
        "b8e6230fb4327ea9ddf57246b00b6999d0b75c6f",
        "9c8abef600fbad09676bd11e29eaff9c357c358c",
        "b0cca1598a457e0d8e23a3a0f6edaf0899998b28",
        "98f10ec6e3d63bf6ebc3ccc73df8b6cae8afad0c",
        "7d8f5d58b4ea3833dbd30142333f4e25f0728ae9",
        "832b829c718a61343210e7eb5b28f55f6d3ef72d",
        "e5bf402a158e49abb6a070528ae0d61512b6856f",
        "b67206223394ce91dc2d2042ff61fb48cbe34c2a",
        "72962b7ff636454e0aabaa882175296d6ce1da83",
        "3cc35334c0030c8178a955a7165bc23fb5b98c78",
        "f2ebcd92726d7cf09ebf204dd31486a351536535",
        "e4f02fab9b9a38bda1401b2111074c8659ab80ff",
        "a56d2f4d7fd0e36a8f48bc0ad0d6837046c98c95",
        "ef60f2de2cfcee6465918a6754947177ba709085",
        "d2017feee30f144e7cb97c573268ee40955d7a86",
        "fdd20e6343fd9d8644a0ad21c5969381f8968b3d",
        "3ed720005584636747541d2454598903efdc3660",
        "907b3e51defc0ddec075ae91756a203a4c1138f1",
        "c0065b54de4719c8eb938ca900fe013817ce674c",
        "0545db489202813397de41d0d16a3f2505c78d68",
        "7218e85f3cfef7d962976e89e5026d5e4bdc4863",
        "eabe9d26e0ac33f48923c8608dabc3769e95cb70",
        "dcc01246f0b84ccc4333592bd0d7060e42173d72",
        "8e67feb32f15b840c0a2adf563da96b152464f4d",
        "f99fe6831f951f0bcea99fe77796944ff2653fd0",
        "25a88813b3c06db2bc3d3ed4b603e04561372e7c",
        "0afea4edcfc71db88de7cc6cca2fd3bc263c789c",
        "8769ba933daa1cd2b20162ddbb47b36423cd41ea",
        "db84bc1eb2d8c30121da6293c25c1a90e0d70348",
        "d2fd3ae822e0117cd9f6db75b757f803db8443d3",
        "f5762e3b80dd58329c5d6ed0ec06ba108c72da9d",
        "13ed0fbe2379f64481c6979ed2a8579fcf2f0acf",
        "5731d0ec88d0a10d52606242f97f3d4c98044bfc",
        "c70e057c2d99b2191ac07366f0c64f94bc41aeaa",
        "d257d3c33709bec4c02218cfb9e286a79f7e3275",
        "769bcd88d8a05be50e4c6199ed131b1e288fb32b",
        "928edce9b923526516f2104b9beb40ec43e267e3",
        "ccb1a286f183df0343a59d8520d467af500d444c",
        "d4f2112c554660a926f3fafab4d41b15d3b5cf10",
        "83a57ea221e4d3736c023e4d4c372122561ce1ff",
        "48d45fb0f612e55ce52ccb00844edc39e9fe1bd2",
        "72f8125cf45449b092ade7b93868c2ffeb701a5c",
        "5153dd4d669819d2b72723c868a1e707ce7c449a",
        "c5b82f750e32188cad5ea7bd102237448c33d8d4",
        "57c32818c414eee7de0cc6520e1500395fc752df",
        "6aa3b0b7beb062b451bb7860ea3be234828f9826",
        "6532032683a23044ab728f1108171f319542828b",
        "8e4a706d954389dd894df0150150ac8e48d47f05",
        "e7caf81c03f5366bdc4401f77bddec23cded337f",
        "5a1f7d0a01bac1bf3713384a6c638fe0e31a2552",
        "48fc5f59213c5c2e219fc8fca607397bd770c072",
        "032841bebb4d01b44802d9b6b0ca287f0e7473ac",
        "aa1ceeecc8a52a1da61905f79ce5bdc2b9ea56c5",
        "f49a4eeebfe4851d53c5c3f67fade15ea8daa759",
        "d3253bb176781be29e2a02710dab501a9614ff95",
        "18a9965bd604373ba380e9c351a8796bd204f332",
        "e82f37aa1dbf8a818d6ab1394bdcd798041f12c6",
        "42da474393aa81703cdddfe671c74e19192b33a6",
        "b6908279efe881a446beeef156e2d4a01f276a3f",
        "7ee42121913687a4f46bb4d5ba74985d63080081",
        "d5116e9a2a8d1af4e05c15eeba10581b3417df55",
        "823ddf66d3c38d42620db82c3f098d8bacad3af8",
        "9998b53972fdf8f2b7a74f72a343f9060a2a9a97",
        "8daec6e313df686aac11e92b6219ae9c6e5bd7bf",
        "e332953ea38e1080ed2e80bdc5ae30a9f0029178",
        "f1b11f9defc5b578455c38b104baa9d41b6473f2",
        "17a2ca7219a50e53ed66d8254842a2f3b2eabcf8",
        "2ac2e1b602fdd1e2d65612fc2f64ba71ad687e62",
        "487e424eafbb7dc791229eeb2436366d6ea7db03",
        "282dc6c257794bce200bb1bac0b5455b19a8b3a3",
        "07f804f62ef0cd76283a01d0b4141a337865d304",
        "9c05d1cae71a12bdb4eea15a212ecee0f5f8bef1",
        "b389524ef254f907660836f17c57c82178119d57",
        "a089d36fd722b2eaea341a40a275d8c4ef1eea61",
        "2e99f8559d303bf75efe417bc8b3420f4ef00007",
        "705e7fe2071210885867c2653218f616466048cd",
        "dd07024712621a63d7f82e8626bf1a2559b2084b",
        "3c2025486d263760126406ab3127427c7c007c40",
        "1060143cbdc7a4ce20b877f52dca875523d26232",
        "838a7472d985fc407c0ab29c29cebc4b13efaf6b",
        "35e0d94f8b852672ebe410ced86f79aa8715544d",
        "473ebdc9b6ffbfd90a56fe6599ab73101fc764d4",
        "ce8e53cf00c6541f3adc0d44dcb66373dfc14c29",
        "2eca1f5afd7203fd812366d76df5d6140d0caee2",
        "fb9b2abde5989ff28f9c64e6d0b1e75a4720a8d4",
        "0a893bca7bd6cdb0bbf240f55829eaebeb662fc6",
        "a7efa2e34a210adb7ec99843b530005391ace433",
        "01816a50d223416a9ed2a6918066e28ccd163968",
        "2f39e37db58ca9b8bb4169f5aeeb9eb99f2353fe",
        "d0b56e727fedef1996ba0d3f456d211c81f95db8",
        "b34f2f81eb15bdde1f9c37128a602d3411ea4d4e",
        "9ac78d963b7bbc621f038d524330e10a1a375410",
        "00e5e5b7daa8c9cfa12ac796aa679a1b3f672fc2",
        "84ad36144296c512ec71002c5703031350feb146",
        "bd58b1f3535db30c3915dee1c3916e0a73ac9152",
        "3641000ebf374fb884176d4e84c720356d9ebcab",
        "bbf7589212e35d8eb1fec514449b4826d82993c4",
        "9f0be5968e80b83a9760c6a585db19538bf903fa",
        "7f54c8bae2c983a294088a9e18471a30b485e1c1",
        "acd5738d679aee5c3dc91a62af84800114f23eae",
        "40d4fcf0b3616beb88bd65f741eb1b0ae7b3cee2",
        "da7138de654e9120c43973f30f6ba18b41b17a98",
        "2b44a321dd7de1c2d86e0070874eed841e4be018",
        "24727b7dffd478786e45635f81ea3d4aa59397f3",
        "850317d890ebe57393777aaebfaafca1a2c49c01",
        "e7b6b0ec9f703d02a12f0fae7db10d0b97af3942",
        "04d6a465deb581cb4f4cc52c6bcb03e693a9228d",
        "58352d1887325f0904b58524f4acba80e6dfa3ce",
        "c671d279be4fa36f185bcb0b23da1e121a93d6db",
        "47a740551260f0f837e7c7b5e4817e628fb163bb",
        "2448c53bcf62e6ab546dbe195e247f4788ae529a",
        "74449a5f6d6cbd774d55b10d5d516d0b0f2daa59",
        "c0982b7f5794090735307455360b47db9866a573",
        "e1c29f6ff543792bee0bff133cd73985e49455ff",
        "e8d7b68447e1f53c30b838051aaed4893ac057c9",
        "0c0b5538c49aaa5b93c32d845298882a5e8909d5",
        "5d1ca4b0381496c4a14844ac8cfa15c6c0ab8ef3",
        "0d81754a6f5811902914b658206668a2d64bb594",
        "c9033fa36d577ac92dfc4b3fbde34fb3f85448cd",
        "6354050444f0c85b90fd6d30af23a56cdb7c5e14",
        "9554a50909212ad70041d4424ff5b4f797f9ba39",
        "87ed5afccd2c870c2c3394562527f100f554dc3d",
        "865435b88bb58912d942d091a2603cfc84a5b5d7",
        "e01e8ffd0016276bfe4efef0d74b3bd0c25413b5",
        "f768f02b225678f3e5366684041c7a6d3d1e10aa",
        "34f560adbf9ea6be669a764eb5baecbaf30fc0a1",
        "97c4c995321c6dd8451a0580801bf9836fa5aecf",
        "9d5761fccaff2d145889b2eada24439d20da6811",
        "2ae277675ce8cdeb965903667d2e36d7611fc2c0",
        "560fe5e41fb23cd92f7558e9b6c384b9bfdf33bd",
        "33e5dc632f7e9c1f5f5d1665f2f3500850368ad2",
        "00797d9c751a1e633b3d9d0711469026d8c84278",
    ];

    /// Helper function to decode the test keys into Vec<Vec<u8>> format.
    /// Returns the same 260 keys used in various bucket collision tests.
    pub fn get_same_bucket_test_keys() -> Vec<Vec<u8>> {
        SAME_BUCKET_TEST_KEYS
            .iter()
            .map(|hex_str| hex::decode(hex_str).expect("Invalid hex in test data"))
            .collect()
    }

    /// Ensures hash function outputs are stable across code changes.
    /// These specific values must never change to maintain consensus compatibility.
    #[test]
    fn test_hash_stability() {
        assert_eq!(hash(b"hello"), 1027176506268606463);
        assert_eq!(hash(b"world"), 2337896903564117184);
        assert_eq!(hash(b"hash test"), 2116618212096523432);
    }

    /// Tests that different nonces produce different hashes for probe sequence generation.
    #[test]
    fn test_hash_with_nonce() {
        let key = b"test_key";

        // Different nonces should produce different hashes
        let hash1 = hash_with_nonce(key, 0);
        let hash2 = hash_with_nonce(key, 1);
        let hash3 = hash_with_nonce(key, u32::MAX);

        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);

        // Same key and nonce should always produce same hash
        assert_eq!(hash_with_nonce(key, 42), hash_with_nonce(key, 42));
    }

    /// Verifies bucket_id returns valid range [NUM_META_BUCKETS, NUM_BUCKETS) for various keys.
    #[test]
    fn test_bucket_id_range() {
        // Test various keys produce valid bucket IDs
        let test_keys: &[&[u8]] = &[b"", b"a", b"test", &[0u8; 32], &[255u8; 32], &[255u8; 1024]];

        for key in test_keys {
            let id = bucket_id(key);
            assert!(
                id >= NUM_META_BUCKETS as BucketId,
                "bucket_id for {:?} is too small: {}",
                key,
                id
            );
            assert!(
                id < (NUM_META_BUCKETS + NUM_KV_BUCKETS) as BucketId,
                "bucket_id for {:?} is too large: {}",
                key,
                id
            );
        }
    }

    /// Tests edge cases: empty keys and large keys that trigger heap allocation path.
    #[test]
    fn test_edge_cases() {
        // Empty key
        assert!(hash(b"") != 0);
        assert!(bucket_id(b"") >= NUM_META_BUCKETS as BucketId);

        // Large key (test stack buffer overflow path)
        let large_key = vec![42u8; 128];
        let hash_large = hash_with_nonce(&large_key, 123);
        assert!(hash_large != 0);
    }

    /// Verifies that all keys in SAME_BUCKET_TEST_KEYS actually hash to the same bucket.
    /// This ensures the test data integrity for bucket collision tests.
    #[test]
    fn test_same_bucket_keys() {
        let keys = get_same_bucket_test_keys();

        // All keys should hash to the same bucket
        let first_bucket = bucket_id(&keys[0]);
        assert_eq!(first_bucket, 131072);
        for (i, key) in keys.iter().enumerate() {
            let key_bucket = bucket_id(key);
            assert_eq!(
                key_bucket, first_bucket,
                "Key {} should hash to bucket {} but got {}",
                i, first_bucket, key_bucket
            );
        }

        // Verify the bucket is a valid data bucket
        assert!(
            first_bucket >= NUM_META_BUCKETS as BucketId,
            "Test keys should map to a data bucket, not metadata bucket"
        );
    }
}
