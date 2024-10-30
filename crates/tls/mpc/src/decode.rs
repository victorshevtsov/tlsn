use std::{ops::BitXor, sync::Arc};

use crate::{MpcTlsError, TlsRole};
use mpz_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    ClearValue, DecodeFutureTyped, Memory, MemoryExt, MemoryType, Repr, StaticSize, Vector, View,
    ViewExt,
};
use mpz_vm_core::{CallBuilder, Vm, VmExt};
use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng, RngCore};

pub(crate) struct Decode {
    role: TlsRole,
    value: Vector<U8>,
    otp_0: Vector<U8>,
    otp_1: Vector<U8>,
    len: usize,
}

impl Decode {
    pub(crate) fn new<V>(vm: &mut V, role: TlsRole, value: Vector<U8>) -> Result<Self, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let len = value.len() * U8::SIZE;
        let otp_0: Vector<U8> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        let otp_1: Vector<U8> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        let decode = Self {
            role,
            value,
            otp_0,
            otp_1,
            len,
        };

        Ok(decode)
    }
}

impl Decode {
    pub(crate) fn private<V>(self, vm: &mut V) -> Result<OneTimePadPrivate, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let otp_value = match self.role {
            TlsRole::Leader => {
                let mut rng = thread_rng();
                let mut otp_value = vec![0_u8; self.len];
                rng.fill_bytes(&mut otp_value);

                vm.mark_private(self.otp_0).map_err(MpcTlsError::vm)?;
                vm.assign(self.otp_0, otp_value.clone())
                    .map_err(MpcTlsError::vm)?;
                Some(otp_value)
            }
            TlsRole::Follower => {
                vm.mark_blind(self.otp_0).map_err(MpcTlsError::vm)?;
                None
            }
        };
        vm.commit(self.otp_0).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(self.otp_0)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output: Vector<U8> = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadPrivate {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }

    pub(crate) fn shared<V>(self, vm: &mut V) -> Result<OneTimePadShared, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let mut rng = thread_rng();
        let mut otp_value = vec![0_u8; self.len];
        rng.fill_bytes(&mut otp_value);

        let mut otp_0 = self.otp_0;
        let mut otp_1 = self.otp_1;
        if let TlsRole::Follower = self.role {
            std::mem::swap(&mut otp_0, &mut otp_1);
        }
        vm.mark_private(otp_0).map_err(MpcTlsError::vm)?;
        vm.mark_blind(otp_1).map_err(MpcTlsError::vm)?;
        vm.assign(otp_0, otp_value.clone())
            .map_err(MpcTlsError::vm)?;

        vm.commit(otp_0).map_err(MpcTlsError::vm)?;
        vm.commit(otp_1).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp_shared(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(otp_0)
            .arg(otp_1)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output: Vector<U8> = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadShared {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }
}

pub(crate) struct OneTimePadPrivate {
    role: TlsRole,
    value: DecodeFutureTyped<BitVec, Vec<u8>>,
    otp: Option<Vec<u8>>,
}

impl OneTimePadPrivate {
    pub(crate) async fn decode(self) -> Result<Option<Vec<u8>>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let otp = self.otp.expect("Otp should be set for leader");
                let out = value
                    .into_iter()
                    .zip(otp.into_iter())
                    .map(|(v, o)| v ^ o)
                    .collect();
                Ok(Some(out))
            }
            TlsRole::Follower => Ok(None),
        }
    }
}

pub(crate) struct OneTimePadShared {
    role: TlsRole,
    value: DecodeFutureTyped<BitVec, Vec<u8>>,
    otp: Vec<u8>,
}

impl OneTimePadShared {
    pub(crate) async fn decode(self) -> Result<Vec<u8>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let value = value
                    .into_iter()
                    .zip(self.otp.into_iter())
                    .map(|(v, o)| v ^ o)
                    .collect();
                Ok(value)
            }
            TlsRole::Follower => Ok(self.otp),
        }
    }
}

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    let input = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp = builder.add_input_by_type(ValueType::new_array::<u8>(len));

    let input = Tracer::new(builder.state(), input);
    let otp = Tracer::new(builder.state(), otp);
    let masked = input ^ otp;
    builder.add_output(masked);

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

/// Builds a circuit for applying one-time pads to secret share the provided values.
pub(crate) fn build_otp_shared(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    let input = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp_0 = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp_1 = builder.add_input_by_type(ValueType::new_array::<u8>(len));

    let input = Tracer::new(builder.state(), input);
    let otp_0 = Tracer::new(builder.state(), otp_0);
    let otp_1 = Tracer::new(builder.state(), otp_1);
    let masked = input ^ otp_0 ^ otp_1;
    builder.add_output(masked);

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
