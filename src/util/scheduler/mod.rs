use ethers_core::types::U256;
use ethers_providers::{Http, Middleware, Provider};
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::ProvingKey,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::fs::{gen_srs, read_params},
};
#[cfg(feature = "halo2-axiom")]
use snark_verifier_sdk::halo2::read_snark;
use snark_verifier_sdk::Snark;
use std::{
    collections::HashMap,
    env::var,
    fmt::Debug,
    fs,
    hash::Hash,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use crate::{
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    Network,
};

use super::circuit::AnyCircuit;

pub mod evm_wrapper;

/// This is an identifier for a specific proof request, consisting of the circuit type together with any data necessary to create the circuit inputs.
/// It should be thought of as a node in a DAG (directed acyclic graph), where the edges specify previous SNARKs this one depends on.
pub trait Task: Clone + Debug {
    /// This is a tag for the type of a circuit, independent of the circuit's inputs.
    /// For example, it can be used to fetch the proving key for the circuit.
    type CircuitType: Copy + Eq + Hash;

    fn circuit_type(&self) -> Self::CircuitType;
    fn type_name(circuit_type: Self::CircuitType) -> String;
    fn name(&self) -> String;

    /// The previous tasks this task depends on (i.e., the edges of the DAG that point to this node).
    fn dependencies(&self) -> Vec<Self>;
}

pub trait SchedulerCommon {
    type CircuitType: Hash + Eq;

    fn config_dir(&self) -> &Path;
    fn data_dir(&self) -> &Path;
    fn pkey_readonly(&self) -> bool;
    fn srs_readonly(&self) -> bool;
    /// Read (or generate) the universal trusted setup by reading configuration file.
    ///
    /// Recommended: Cache the params in a hashmap if they are not already cached.
    fn get_params(&self, k: u32) -> Arc<ParamsKZG<Bn256>>;
    /// Fetch pkey from cache (intended to be from HashMap).
    fn get_pkey(&self, circuit_type: &Self::CircuitType) -> Option<Arc<ProvingKey<G1Affine>>>;
    /// Assumes this uses the same HashMap as `get_pkey`.
    fn insert_pkey(&self, circuit_type: Self::CircuitType, pkey: ProvingKey<G1Affine>);
}

/// A basic implementation of `SchedulerCommon` with support for ETH JSON-RPC requests.
pub struct EthScheduler<T: Task> {
    /// Specifies if universal trusted setup should only be read (production mode) or randomly generated (UNSAFE non-production mode)
    srs_read_only: bool,
    /// Specifies if new proving keys should be generated or not. If `read_only` is true, then `srs_read_only` is also force to be true.
    read_only: bool,
    config_dir: PathBuf,
    data_dir: PathBuf,

    pub pkeys: RwLock<HashMap<T::CircuitType, Arc<ProvingKey<G1Affine>>>>,
    pub degree: RwLock<HashMap<T::CircuitType, u32>>,
    pub params: RwLock<HashMap<u32, Arc<ParamsKZG<Bn256>>>>,
    pub provider: Arc<Provider<Http>>,
    pub network: Network,

    _marker: PhantomData<T>,
}

impl<T: Task> EthScheduler<T> {
    pub fn new(
        network: Network,
        mut srs_read_only: bool,
        read_only: bool,
        config_dir: PathBuf,
        data_dir: PathBuf,
    ) -> Self {
        let provider_url = var("JSON_RPC_URL").expect("JSON_RPC_URL not found");
        let provider =
            Provider::<Http>::try_from(provider_url).expect("could not instantiate HTTP Provider");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let chain_id = provider.get_chainid().await.unwrap();
            match network {
                Network::Mainnet => {
                    assert_eq!(chain_id, U256::from(1));
                }
                Network::Goerli => {
                    assert_eq!(chain_id, U256::from(5));
                }
            }
        });
        fs::create_dir_all(&config_dir).expect("could not create config directory");
        fs::create_dir_all(&data_dir).expect("could not create data directory");
        srs_read_only = srs_read_only || read_only;
        #[cfg(feature = "production")]
        {
            srs_read_only = true;
        }
        Self {
            srs_read_only,
            read_only,
            config_dir,
            data_dir,
            pkeys: Default::default(),
            degree: Default::default(),
            params: Default::default(),
            provider: Arc::new(provider),
            network,
            _marker: PhantomData,
        }
    }
}

impl<T: Task> SchedulerCommon for EthScheduler<T> {
    type CircuitType = T::CircuitType;

    fn config_dir(&self) -> &Path {
        self.config_dir.as_path()
    }
    fn data_dir(&self) -> &Path {
        self.data_dir.as_path()
    }
    fn srs_readonly(&self) -> bool {
        self.srs_read_only
    }
    fn pkey_readonly(&self) -> bool {
        self.read_only
    }
    fn get_params(&self, k: u32) -> Arc<ParamsKZG<Bn256>> {
        if let Some(params) = self.params.read().unwrap().get(&k) {
            return Arc::clone(params);
        }
        let params = if self.srs_readonly() { read_params(k) } else { gen_srs(k) };
        let params = Arc::new(params);
        self.params.write().unwrap().insert(k, Arc::clone(&params));
        params
    }
    fn get_pkey(&self, circuit_type: &Self::CircuitType) -> Option<Arc<ProvingKey<G1Affine>>> {
        self.pkeys.read().unwrap().get(circuit_type).map(Arc::clone)
    }
    fn insert_pkey(&self, circuit_type: Self::CircuitType, pkey: ProvingKey<G1Affine>) {
        self.pkeys.write().unwrap().insert(circuit_type, Arc::new(pkey));
    }
}

/// A scheduler that can recursively generate SNARKs for a DAG of tasks. The directed acyclic graph (DAG) is implicitly
/// defined by the `Task` implementation and `get_circuit`. For any task, either a snark or calldata + on-chain verifier can be generated.
pub trait Scheduler: SchedulerCommon<CircuitType = <Self::Task as Task>::CircuitType> {
    type Task: Task;
    /// The intended use is that `CircuitRouter` is an enum containing the different `PreCircuit`s that `Task` can become in the `get_circuit` function.
    // TODO: better way to do this with macros? `PreCircuit` is not object safe so cannot use `dyn`
    type CircuitRouter: AnyCircuit + Clone;

    /// Returns the degree of the circuit from file.
    ///
    /// Recommended: use `HashMap` to cache this.
    fn get_degree(&self, circuit_type: <Self::Task as Task>::CircuitType) -> u32;

    /// `prev_snarks` is assumed to be the SNARKs associated to the previous tasks in `task.dependencies()`. From those snarks (if any), this
    /// function constructs the pre-circuit for this task.
    fn get_circuit(&self, task: Self::Task, prev_snarks: Vec<Snark>) -> Self::CircuitRouter;

    // ==== automatically generated functions below ====

    /// The path to the file with the circuit configuration pinning.
    fn pinning_path(&self, circuit_type: <Self::Task as Task>::CircuitType) -> PathBuf {
        self.config_dir().join(format!("{}.json", Self::Task::type_name(circuit_type)))
    }
    fn pkey_path(&self, circuit_type: <Self::Task as Task>::CircuitType) -> PathBuf {
        self.data_dir().join(format!("{}.pk", Self::Task::type_name(circuit_type)))
    }
    fn yul_path(&self, circuit_type: <Self::Task as Task>::CircuitType) -> PathBuf {
        self.data_dir().join(format!("{}.yul", Self::Task::type_name(circuit_type)))
    }
    fn snark_path(&self, task: &Self::Task) -> PathBuf {
        self.data_dir().join(format!("{}.snark", task.name()))
    }
    fn calldata_path(&self, task: &Self::Task) -> PathBuf {
        self.data_dir().join(format!("{}.calldata", task.name()))
    }

    // recursively generates necessary circuits and snarks to create snark
    fn get_snark(&self, task: Self::Task) -> Snark {
        let snark_path = self.snark_path(&task);
        #[cfg(feature = "halo2-axiom")]
        if let Ok(snark) = read_snark(snark_path.clone()) {
            return snark;
        }
        let read_only = self.pkey_readonly();

        // Recursively generate the SNARKs for the dependencies of this task.
        let dep_snarks: Vec<Snark> =
            task.dependencies().into_iter().map(|dep| self.get_snark(dep)).collect();

        let circuit_type = task.circuit_type();
        let k = self.get_degree(circuit_type);
        let params = &self.get_params(k);
        // Construct the pre-circuit for this task from the dependency SNARKs.
        let pre_circuit = self.get_circuit(task, dep_snarks);
        let pk_path = self.pkey_path(circuit_type);
        let pinning_path = self.pinning_path(circuit_type);

        let pk = if let Some(pk) = self.get_pkey(&circuit_type) {
            pk
        } else {
            let pk =
                pre_circuit.clone().read_or_create_pk(params, pk_path, &pinning_path, read_only);
            self.insert_pkey(circuit_type, pk);
            self.get_pkey(&circuit_type).unwrap()
        };
        let snark_path = Some(snark_path);
        pre_circuit.gen_snark_shplonk(params, &pk, &pinning_path, snark_path)
    }

    #[cfg(feature = "evm")]
    fn get_calldata(&self, task: Self::Task, generate_smart_contract: bool) -> String {
        // TODO: some shared code with `get_snark`; clean up somehow

        let calldata_path = self.calldata_path(&task);
        if let Ok(calldata) = fs::read_to_string(&calldata_path) {
            // calldata is serialized as a hex string
            return calldata;
        }

        let dep_snarks: Vec<Snark> =
            task.dependencies().into_iter().map(|dep| self.get_snark(dep)).collect();

        let circuit_type = task.circuit_type();
        let k = self.get_degree(circuit_type);
        let params = &self.get_params(k);
        // Construct the pre-circuit for this task from the dependency SNARKs.
        let pre_circuit = self.get_circuit(task, dep_snarks);
        let pk_path = self.pkey_path(circuit_type);
        let pinning_path = self.pinning_path(circuit_type);

        let pk = if let Some(pk) = self.get_pkey(&circuit_type) {
            pk
        } else {
            let read_only = self.pkey_readonly();
            let pk =
                pre_circuit.clone().read_or_create_pk(params, pk_path, &pinning_path, read_only);
            self.insert_pkey(circuit_type, pk);
            self.get_pkey(&circuit_type).unwrap()
        };

        let deployment_code = generate_smart_contract.then(|| {
            pre_circuit.clone().gen_evm_verifier_shplonk(params, &pk, self.yul_path(circuit_type))
        });
        pre_circuit.gen_calldata(params, &pk, pinning_path, calldata_path, deployment_code)
    }
}
