// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: mta.proto

#include "mta.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
extern PROTOBUF_INTERNAL_EXPORT_zkp_2eproto ::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<1> scc_info_DLogProof_zkp_2eproto;
namespace safeheron {
namespace proto {
class MtaMessageBDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<MtaMessageB> _instance;
} _MtaMessageB_default_instance_;
}  // namespace proto
}  // namespace safeheron
static void InitDefaultsscc_info_MtaMessageB_mta_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::safeheron::proto::_MtaMessageB_default_instance_;
    new (ptr) ::safeheron::proto::MtaMessageB();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<1> scc_info_MtaMessageB_mta_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 1, 0, InitDefaultsscc_info_MtaMessageB_mta_2eproto}, {
      &scc_info_DLogProof_zkp_2eproto.base,}};

static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_mta_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_mta_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_mta_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_mta_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::safeheron::proto::MtaMessageB, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::safeheron::proto::MtaMessageB, c_b_),
  PROTOBUF_FIELD_OFFSET(::safeheron::proto::MtaMessageB, dlog_proof_b_),
  PROTOBUF_FIELD_OFFSET(::safeheron::proto::MtaMessageB, dlog_proof_beta_tag_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::safeheron::proto::MtaMessageB)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::safeheron::proto::_MtaMessageB_default_instance_),
};

const char descriptor_table_protodef_mta_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\tmta.proto\022\017safeheron.proto\032\tzkp.proto\""
  "\205\001\n\013MtaMessageB\022\013\n\003c_b\030\001 \001(\t\0220\n\014dlog_pro"
  "of_b\030\002 \001(\0132\032.safeheron.proto.DLogProof\0227"
  "\n\023dlog_proof_beta_tag\030\003 \001(\0132\032.safeheron."
  "proto.DLogProofb\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_mta_2eproto_deps[1] = {
  &::descriptor_table_zkp_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase*const descriptor_table_mta_2eproto_sccs[1] = {
  &scc_info_MtaMessageB_mta_2eproto.base,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_mta_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_mta_2eproto = {
  false, false, descriptor_table_protodef_mta_2eproto, "mta.proto", 183,
  &descriptor_table_mta_2eproto_once, descriptor_table_mta_2eproto_sccs, descriptor_table_mta_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_mta_2eproto::offsets,
  file_level_metadata_mta_2eproto, 1, file_level_enum_descriptors_mta_2eproto, file_level_service_descriptors_mta_2eproto,
};

// Force running AddDescriptors() at dynamic initialization time.
static bool dynamic_init_dummy_mta_2eproto = (static_cast<void>(::PROTOBUF_NAMESPACE_ID::internal::AddDescriptors(&descriptor_table_mta_2eproto)), true);
namespace safeheron {
namespace proto {

// ===================================================================

class MtaMessageB::_Internal {
 public:
  static const ::safeheron::proto::DLogProof& dlog_proof_b(const MtaMessageB* msg);
  static const ::safeheron::proto::DLogProof& dlog_proof_beta_tag(const MtaMessageB* msg);
};

const ::safeheron::proto::DLogProof&
MtaMessageB::_Internal::dlog_proof_b(const MtaMessageB* msg) {
  return *msg->dlog_proof_b_;
}
const ::safeheron::proto::DLogProof&
MtaMessageB::_Internal::dlog_proof_beta_tag(const MtaMessageB* msg) {
  return *msg->dlog_proof_beta_tag_;
}
void MtaMessageB::clear_dlog_proof_b() {
  if (GetArena() == nullptr && dlog_proof_b_ != nullptr) {
    delete dlog_proof_b_;
  }
  dlog_proof_b_ = nullptr;
}
void MtaMessageB::clear_dlog_proof_beta_tag() {
  if (GetArena() == nullptr && dlog_proof_beta_tag_ != nullptr) {
    delete dlog_proof_beta_tag_;
  }
  dlog_proof_beta_tag_ = nullptr;
}
MtaMessageB::MtaMessageB(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:safeheron.proto.MtaMessageB)
}
MtaMessageB::MtaMessageB(const MtaMessageB& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  c_b_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_c_b().empty()) {
    c_b_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_c_b(), 
      GetArena());
  }
  if (from._internal_has_dlog_proof_b()) {
    dlog_proof_b_ = new ::safeheron::proto::DLogProof(*from.dlog_proof_b_);
  } else {
    dlog_proof_b_ = nullptr;
  }
  if (from._internal_has_dlog_proof_beta_tag()) {
    dlog_proof_beta_tag_ = new ::safeheron::proto::DLogProof(*from.dlog_proof_beta_tag_);
  } else {
    dlog_proof_beta_tag_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:safeheron.proto.MtaMessageB)
}

void MtaMessageB::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_MtaMessageB_mta_2eproto.base);
  c_b_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  ::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
      reinterpret_cast<char*>(&dlog_proof_b_) - reinterpret_cast<char*>(this)),
      0, static_cast<size_t>(reinterpret_cast<char*>(&dlog_proof_beta_tag_) -
      reinterpret_cast<char*>(&dlog_proof_b_)) + sizeof(dlog_proof_beta_tag_));
}

MtaMessageB::~MtaMessageB() {
  // @@protoc_insertion_point(destructor:safeheron.proto.MtaMessageB)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void MtaMessageB::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
  c_b_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (this != internal_default_instance()) delete dlog_proof_b_;
  if (this != internal_default_instance()) delete dlog_proof_beta_tag_;
}

void MtaMessageB::ArenaDtor(void* object) {
  MtaMessageB* _this = reinterpret_cast< MtaMessageB* >(object);
  (void)_this;
}
void MtaMessageB::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void MtaMessageB::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const MtaMessageB& MtaMessageB::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_MtaMessageB_mta_2eproto.base);
  return *internal_default_instance();
}


void MtaMessageB::Clear() {
// @@protoc_insertion_point(message_clear_start:safeheron.proto.MtaMessageB)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  c_b_.ClearToEmpty();
  if (GetArena() == nullptr && dlog_proof_b_ != nullptr) {
    delete dlog_proof_b_;
  }
  dlog_proof_b_ = nullptr;
  if (GetArena() == nullptr && dlog_proof_beta_tag_ != nullptr) {
    delete dlog_proof_beta_tag_;
  }
  dlog_proof_beta_tag_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* MtaMessageB::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // string c_b = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_c_b();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "safeheron.proto.MtaMessageB.c_b"));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .safeheron.proto.DLogProof dlog_proof_b = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr = ctx->ParseMessage(_internal_mutable_dlog_proof_b(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .safeheron.proto.DLogProof dlog_proof_beta_tag = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 26)) {
          ptr = ctx->ParseMessage(_internal_mutable_dlog_proof_beta_tag(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* MtaMessageB::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:safeheron.proto.MtaMessageB)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // string c_b = 1;
  if (this->c_b().size() > 0) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_c_b().data(), static_cast<int>(this->_internal_c_b().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "safeheron.proto.MtaMessageB.c_b");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_c_b(), target);
  }

  // .safeheron.proto.DLogProof dlog_proof_b = 2;
  if (this->has_dlog_proof_b()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        2, _Internal::dlog_proof_b(this), target, stream);
  }

  // .safeheron.proto.DLogProof dlog_proof_beta_tag = 3;
  if (this->has_dlog_proof_beta_tag()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        3, _Internal::dlog_proof_beta_tag(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:safeheron.proto.MtaMessageB)
  return target;
}

size_t MtaMessageB::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:safeheron.proto.MtaMessageB)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string c_b = 1;
  if (this->c_b().size() > 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_c_b());
  }

  // .safeheron.proto.DLogProof dlog_proof_b = 2;
  if (this->has_dlog_proof_b()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *dlog_proof_b_);
  }

  // .safeheron.proto.DLogProof dlog_proof_beta_tag = 3;
  if (this->has_dlog_proof_beta_tag()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *dlog_proof_beta_tag_);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void MtaMessageB::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:safeheron.proto.MtaMessageB)
  GOOGLE_DCHECK_NE(&from, this);
  const MtaMessageB* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<MtaMessageB>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:safeheron.proto.MtaMessageB)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:safeheron.proto.MtaMessageB)
    MergeFrom(*source);
  }
}

void MtaMessageB::MergeFrom(const MtaMessageB& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:safeheron.proto.MtaMessageB)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.c_b().size() > 0) {
    _internal_set_c_b(from._internal_c_b());
  }
  if (from.has_dlog_proof_b()) {
    _internal_mutable_dlog_proof_b()->::safeheron::proto::DLogProof::MergeFrom(from._internal_dlog_proof_b());
  }
  if (from.has_dlog_proof_beta_tag()) {
    _internal_mutable_dlog_proof_beta_tag()->::safeheron::proto::DLogProof::MergeFrom(from._internal_dlog_proof_beta_tag());
  }
}

void MtaMessageB::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:safeheron.proto.MtaMessageB)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void MtaMessageB::CopyFrom(const MtaMessageB& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:safeheron.proto.MtaMessageB)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool MtaMessageB::IsInitialized() const {
  return true;
}

void MtaMessageB::InternalSwap(MtaMessageB* other) {
  using std::swap;
  _internal_metadata_.Swap<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(&other->_internal_metadata_);
  c_b_.Swap(&other->c_b_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(MtaMessageB, dlog_proof_beta_tag_)
      + sizeof(MtaMessageB::dlog_proof_beta_tag_)
      - PROTOBUF_FIELD_OFFSET(MtaMessageB, dlog_proof_b_)>(
          reinterpret_cast<char*>(&dlog_proof_b_),
          reinterpret_cast<char*>(&other->dlog_proof_b_));
}

::PROTOBUF_NAMESPACE_ID::Metadata MtaMessageB::GetMetadata() const {
  return GetMetadataStatic();
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace safeheron
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::safeheron::proto::MtaMessageB* Arena::CreateMaybeMessage< ::safeheron::proto::MtaMessageB >(Arena* arena) {
  return Arena::CreateMessageInternal< ::safeheron::proto::MtaMessageB >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>