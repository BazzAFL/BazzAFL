#include "afl-fuzz.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
/* 
  BazzAFL
*/


/* BazzAFL */

FILE* MB_record;
struct queue_entry *delete_buf[100000];
u32 delete_num = 0;
/* Entropic */
GQueue* RareFeatures;
u32 MaxNumberOfRarestFeatures = 100;
int FreqOfMostAbundantRareFeature = 256;
int FeatureFrequencyThreshold = 255;
u16 GlobalFeatureFreqs[MAP_SIZE];
int Delete;
int MostAbundantRareFeatureIndices[2];
u8 DistributionNeedsUpdate = 1; // If the InputCorpus needs update energy
double Weights[5];
u8 NewFeatureId[MAP_SIZE];

float EnergyMaxEdge;
float EnergyMinEdge;
float EnergyMaxMetric[4];
float EnergyMinMetric[4];
int RareFeatureNum = 0;

/* Entropic */
/* BazzAFL */

u64        last_ac_time,
           last_func_time,
           last_oom_time,
           last_oob_time;
u32 NumberOfSubSeed[4] = {0};

// const char s[2] = "/";

struct queue_entry *queue_temp;

/* Part.0 Multibugs Metric Related */
#define SeedType 5
u32 max_func_count_global = 0;  // global max func count
u32 max_ac_count_global = 0;   // global max ac count
u32 max_oom_size_global = 0;   // global max oom size
float max_oob_total_global = 0;   // global max oom size
int cur_seed_type=0;      // current selected seed type 
u8 mb_check_ret[SeedType - 1] = {0};
char* mb_dir_name[SeedType] = {"afl_path","func","ac","oom","oob"};

/* Seed Types */
enum {
  /* 00 */ SEED_PATH,
  /* 01 */ SEED_FUNC,
  /* 02 */ SEED_AC,
  /* 03 */ SEED_OOM,
  /* 04 */ SEED_OOB,
};
/* Part.1 Seed Priorization */
int queue_rank = 0;
u32 P_num, N_num, D_num, R_num;     /* Number of each seed corp         */
u8 compare_level = 0, has_winner = 0, exit_flag = 0;
int NumInQueue = 0;

/* Part.1 Seed Priorization */

/* Part.2 Seed Selection */

/* Part.2 Seed Selection */
/* Part.3 Entropic */
u64 cksum_temp = 0;

// traverse all the node in tree
inline gboolean iter_all_edge(gpointer key, gpointer value, gpointer userdata) {
  u32 LocalIncidence = GPOINTER_TO_UINT(value) + 1;
  EnergyUnit *eu = (EnergyUnit *)userdata;
  // printf("iter_all_edge LocalIncidence:%d\n", LocalIncidence);
  if(LocalIncidence > 1){
    eu->Energy -= LocalIncidence * log(LocalIncidence);
    eu->SumIncidence += LocalIncidence;
  }
  return FALSE;
}


/* Glib */
// static void show_stats(void);

// meet all conditions
inline u8 dominate_level_0(struct queue_entry* a, struct queue_entry* b)
{
  if(a->exec_us<b->exec_us){
    if(a->bitmap_size>b->bitmap_size){
      if(a->max_func_count>=b->max_func_count){
        if(a->max_oom_size>=b->max_oom_size){
          if(a->max_ac_count>=b->max_ac_count){
            if(a->max_oob_total>=b->max_oob_total){
              return 1;
            }
          }
        }
      }
    }
  }
  return 0;
}

// delete exec_us cond
inline u8 dominate_level_1(struct queue_entry* a, struct queue_entry* b)
{
  if(a->bitmap_size>b->bitmap_size){
    if(a->max_func_count>=b->max_func_count){
      if(a->max_oom_size>=b->max_oom_size){
        if(a->max_ac_count>=b->max_ac_count){
          if(a->max_oob_total>=b->max_oob_total){
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

// delete bitmap cond
inline u8 dominate_level_2(struct queue_entry* a, struct queue_entry* b)
{
  if(a->max_ac_count>b->max_ac_count){
    if(a->max_func_count>b->max_func_count){
      if(a->max_oom_size>b->max_oom_size){
        if(a->max_oob_total>b->max_oob_total){
          return 1;
        }
      }
    }
  }
  return 0;
}

// delete ac cond
inline u8 dominate_level_3(struct queue_entry* a, struct queue_entry* b)
{
  if(a->max_func_count>=b->max_func_count){
    if(a->max_oom_size>=b->max_oom_size){
      if(a->max_oob_total>=b->max_oob_total){
        return 1;
      }
    }
  }
  return 0;
}
// delete func cond
inline u8 dominate_level_4(struct queue_entry* a, struct queue_entry* b)
{
  if(a->max_oom_size>=b->max_oom_size){
    if(a->max_oob_total>=b->max_oob_total){
      return 1;
    }
  }
  return 0;
}
inline u8 update_ranks(struct queue_entry* a, struct queue_entry* b,u8 level)
{
  u8 win_ret = 0;
  if(unlikely(a==b))
  {
    return 0;
  }
  switch (level)
  {
    case 0:
      if(dominate_level_0(a,b)){
        b->rank += 1;
        win_ret = 1;
      }
      if(dominate_level_0(b,a)){
        a->rank += 1;
        win_ret = 1;
      }
      break;
    
    case 1:
      if(dominate_level_1(a,b)){
        b->rank += 1;
        win_ret = 1;
      }
      if(dominate_level_1(b,a)){
        a->rank += 1;
        win_ret = 1;
      }
      break;

    case 2:
      if(dominate_level_2(a,b)){
        b->rank += 1;
        win_ret = 1;
      }
      if(dominate_level_2(b,a)){
        a->rank += 1;
        win_ret = 1;
      }
      break;

    case 3:
      if(dominate_level_3(a,b)){
        b->rank += 1;
        win_ret = 1;
      }
      if(dominate_level_3(b,a)){
        a->rank += 1;
        win_ret = 1;
      }
      break;

    case 4:
      if(dominate_level_4(a,b)){
        b->rank += 1;
        win_ret = 1;
      }
      if(dominate_level_4(b,a)){
        a->rank += 1;
        win_ret = 1;
      }
      break;

    default:
      break;
  }
  return win_ret;
}
/* BazzAFL */
/* Glib */
inline void RankAddOne(gpointer selfdata,gpointer userdata)
{
  struct queue_entry *q = (struct queue_entry *)selfdata;
  q->rank = queue_rank + 1;
  N_num++;
}
inline void RankSetToZero(gpointer selfdata,gpointer userdata)
{
  struct queue_entry *q = (struct queue_entry *)selfdata;
  if(likely(q))
    q->rank = 0;
}
inline void AddToQD(gpointer selfdata,gpointer userdata)
{
  struct queue_entry *q = NULL;
  if (selfdata)
    q = (struct queue_entry *)selfdata;
  g_queue_push_tail(MBQueue.D, q);

  // seed from N:q_rank=4  seed from R:q_rank=8
  q->q_rank = 2; 
}
inline void AddToQP(gpointer selfdata,gpointer userdata)
{
  struct queue_entry *q = (struct queue_entry *)selfdata;
  D_num++; // to delete
  if (q->rank == queue_rank)
  {
    q = (struct queue_entry *)g_queue_pop_nth(MBQueue.D, NumInQueue);
    if(q)
    {
      g_queue_push_tail(MBQueue.P, q);
      q->q_rank = 1;
    }
    NumInQueue--;
    D_num--; // to delete
    P_num++; // to delete
  }
  NumInQueue++;
}
inline void IterIn(gpointer selfdata,gpointer userdata)
{
  // printf("IterIn selfdata:%d userdata:%d\n", selfdata->rank, userdata->rank);
  if(selfdata==userdata || !selfdata || !userdata)
    return;
  struct queue_entry *q = (struct queue_entry *)selfdata;
  struct queue_entry *p = (struct queue_entry *)userdata;
  has_winner = update_ranks(q, p, compare_level);
  if(unlikely(has_winner))
    exit_flag = 1;
}
inline void IterOutD(gpointer selfdata,gpointer userdata)
{
  // printf("OutD selfdata rank:%d\n", selfdata->rank);
  g_queue_foreach(MBQueue.D, (GFunc)IterIn, selfdata);
}
inline void IterOutR(gpointer selfdata,gpointer userdata)
{
  g_queue_foreach(MBQueue.R, (GFunc)IterIn, selfdata);
}

/* Glib */
/* BazzAFL */

void supply_for_P(afl_state_t *afl)
{

  u64 prev_queued_in = 0;
  N_num = 0;

  // n.rank=queue_rank +1 for n in N
  g_queue_foreach(MBQueue.N, (GFunc)RankAddOne, NULL);
  // printf("N_num:%d\n", N_num);
  // combine queue_N into queue_D
  g_queue_foreach(MBQueue.N, (GFunc)AddToQD, GINT_TO_POINTER(4));

  exit_flag = 0,compare_level=0;
  while(!exit_flag)
  {
    has_winner = 0;
    if(g_queue_is_empty(MBQueue.N))
      break;
    // printf("MBQueue.N size:%d\n", g_queue_get_length(MBQueue.N));
    g_queue_foreach(MBQueue.N, (GFunc)IterOutD, NULL);
    compare_level++;
    if(compare_level >= 5){
      // printf("update rank in D: still no new seed that has been improved rank\n");
      exit_flag = 1;;
    }
  }

  /* N=0 */
  g_queue_clear(MBQueue.N);
  N_num = 0;

  if(g_queue_is_empty(MBQueue.D)){
    // printf("D is empty and no new join from N\n");
    afl->queue_cycle += 1;
    queue_rank = -1;
    // r.rank=0 for r in R
    g_queue_foreach(MBQueue.R, (GFunc)RankSetToZero, NULL);
    /* If we had a full queue cycle with no new finds, try
        recombination strategies next. */
    // printf("SetToZero\n");
    if (afl->queued_items == prev_queued_in) {

      if (afl->use_splicing) afl->cycles_wo_finds++; else afl->use_splicing = 1;

    } else afl->cycles_wo_finds = 0;

    prev_queued_in = afl->queued_items;

    exit_flag = 0, compare_level = 0;

    // update ranks in R
    while(!exit_flag){
      has_winner = 0;
      if(g_queue_is_empty(MBQueue.R))
        break;
      g_queue_foreach(MBQueue.R, (GFunc)IterOutR, NULL);
      compare_level++;
      if (compare_level >= 5){
        // printf("update rank in R: still no new seed that has been improved rank\n");
        exit_flag = 1;
      }
    }

    // combine queue_R into queue_D
    g_queue_foreach(MBQueue.R, (GFunc)AddToQD, GINT_TO_POINTER(8));
    // printf("AddToD from R\n");
    /* R=0 */
    if(!g_queue_is_empty(MBQueue.R))
    {
      g_queue_clear(MBQueue.R);
      // printf("Clear Queue R \n");
    }

    R_num = 0;
    /* R=0 */

    // show_stats();

    if (afl->not_on_tty) {
      ACTF("Entering queue cycle %llu.", afl->queue_cycle);
      fflush(stdout);
    }
  }

  queue_rank ++; // because P is empty now,so we need to up the rank to let more seeds from D into P

  // for d in D
  // if d.rank == queue_rank then
  // pop d from D
  // push d into P
  D_num = 0;
  // printf("queue_rank++: %d\n", queue_rank);
  NumInQueue = 0;
  g_queue_foreach(MBQueue.D, (GFunc)AddToQP, NULL);
  // printf("supply_for_P D_num:%d P_num:%d\n", D_num, P_num);
}

inline void update_multibugs_seed(struct queue_entry* q){
  if(unlikely(q->func_count > max_func_count_global)){
    max_func_count_global = q->func_count;
  }
  if(unlikely(q->oom_size > max_oom_size_global)){
    max_oom_size_global = q->oom_size;
  }
  if(unlikely(q->ac_count > max_ac_count_global)){
    max_ac_count_global = q->ac_count;
  }
  if(unlikely(q->oob_total > max_oob_total_global)){
    max_oob_total_global = q->oob_total;
  }
}

/* Entropic */


inline void FindRightLocInsert(GHashTable *t,u32 Idx)
{
  u32 node_value = GPOINTER_TO_UINT(g_hash_table_lookup(t, GUINT_TO_POINTER(Idx)));
  if (node_value)
  {
    g_hash_table_insert(t, GUINT_TO_POINTER(Idx), GUINT_TO_POINTER(node_value + 1));
  }
  else
  {
    g_hash_table_insert(t, GUINT_TO_POINTER(Idx), GUINT_TO_POINTER(1));
  }
  // g_hash_table_foreach(t, (GHFunc)show, NULL);
  // printf("metric hash table size:%d\n",g_hash_table_size(t));
}

void UpdateEnergy(afl_state_t *afl, struct queue_entry* q)
{

  q->Energy=0.0;
  q->SumIncidence=0;
  int AbdIncidence = q->NumExecutedMutations + 1;
  // u32 LocalIncidence = 0;

  EnergyUnit Edge;
  Edge.Energy = 0;
  Edge.SumIncidence = 0;
  EnergyUnit Metric[4];
  memset(Metric, 0, sizeof(Metric));

  // Edge Part
  // printf("edge hash table size:%d\n",g_hash_table_size(q->feature_edge));
  g_hash_table_foreach(q->feature_edge, (GHFunc)iter_all_edge, &Edge);
  int NumberOfRareFeatures = g_queue_get_length(RareFeatures);
  Edge.SumIncidence += (NumberOfRareFeatures - g_hash_table_size(q->feature_edge));
  Edge.Energy -= AbdIncidence * log(AbdIncidence);
  Edge.SumIncidence += AbdIncidence;

  if (Edge.SumIncidence != 0)
    Edge.Energy = (Edge.Energy / Edge.SumIncidence) + log(Edge.SumIncidence);

  // printf("Updated Edge Energy:%f\n",Edge.Energy);

  // Edge Part Normalization
  if(likely(EnergyMinEdge)){
    if(Edge.Energy < EnergyMinEdge){
      EnergyMinEdge = Edge.Energy;
    }
  }else{
    EnergyMinEdge = Edge.Energy;
  }

  if(Edge.Energy >= EnergyMaxEdge){
    EnergyMaxEdge = Edge.Energy;
    Edge.Energy = 1;
  }else{
    Edge.Energy = (Edge.Energy - EnergyMinEdge) / (EnergyMaxEdge - EnergyMinEdge);
  }
  q->SumIncidence += Edge.SumIncidence;
  q->Energy += Edge.Energy;

  // Metric Part
  for (int i = 0; i < 4; i++)
  {
    // printf("metric %d hash table size:%d\n",i,g_hash_table_size(q->feature_metric[i]));
    g_hash_table_foreach(q->feature_metric[i], (GHFunc)iter_all_edge, Metric+i);
    Metric[i].SumIncidence += (afl->queued_items - g_hash_table_size(q->feature_metric[i]));
    Metric[i].Energy -= AbdIncidence * log(AbdIncidence);
    Metric[i].SumIncidence += AbdIncidence;
    if (Metric[i].SumIncidence != 0)
      Metric[i].Energy = (Metric[i].Energy / Metric[i].SumIncidence) + log(Metric[i].SumIncidence);
    // printf("Updated Metric %d Energy:%f\n",i,Metric[i].Energy);
    // Metric Part Normalization
    if(likely(EnergyMinMetric[i])){
      if(Metric[i].Energy < EnergyMinMetric[i]){
        EnergyMinMetric[i] = Metric[i].Energy;
      }
    }else{
      EnergyMinMetric[i] = Metric[i].Energy;
    }

    if(Metric[i].Energy >= EnergyMaxMetric[i]){
      EnergyMaxMetric[i] = Metric[i].Energy;
      Metric[i].Energy = 1;
    }else{
      Metric[i].Energy = (Metric[i].Energy - EnergyMinMetric[i]) / (EnergyMaxMetric[i] - EnergyMinMetric[i]);
    }
    q->SumIncidence += Metric[i].SumIncidence;
    q->Energy +=  Metric[i].Energy;
  }

  // printf("Updated Seed type:%d  Energy:%f \n",q->seed_type,q->Energy);
  q->NeedsEnergyUpdate = 0;

}

// Here we only have 5 seeds to arrange their energy, and we only update these 5 seeds
void UpdateCorpusDistribution(afl_state_t *afl, struct queue_entry* afl_seed)
{
  // update afl_seed and its 4 sub_seed
  if(afl_seed->NeedsEnergyUpdate){
    UpdateEnergy(afl,afl_seed);
  }
  double TotalWeights = 0.0;
  u8 has_sub_seed = 0;
  u8 too_much = 0;
  memset(Weights, 0, sizeof(Weights));
  Weights[0] = afl_seed->Energy;
  TotalWeights += Weights[0];

  if(afl_seed->func_seed){
    if(afl_seed->func_seed->NeedsEnergyUpdate){
      UpdateEnergy(afl,afl_seed->func_seed);
    }
    Weights[1] = afl_seed->func_seed->Energy;
    TotalWeights += Weights[1];
    has_sub_seed = 1;
  }
  if(afl_seed->ac_seed){
    if(afl_seed->ac_seed->NeedsEnergyUpdate){
      UpdateEnergy(afl,afl_seed->ac_seed);
    }
    Weights[2] = afl_seed->ac_seed->Energy;
    TotalWeights += Weights[2];
    has_sub_seed = 1;
  }    
  if(afl_seed->oom_seed){
    if(afl_seed->oom_seed->NeedsEnergyUpdate){
      UpdateEnergy(afl,afl_seed->oom_seed);
    }
    Weights[3] = afl_seed->oom_seed->Energy;
    TotalWeights += Weights[3];
    has_sub_seed = 1;
  }
  if(afl_seed->oob_seed){
    if(afl_seed->oob_seed->NeedsEnergyUpdate){
      UpdateEnergy(afl,afl_seed->oob_seed);
    }
    Weights[4] = afl_seed->oob_seed->Energy;
    TotalWeights += Weights[4];
    has_sub_seed = 1;
  }
  // in case master seed has too much weight
  if(likely(TotalWeights > 0)){
    if(Weights[0] / TotalWeights > 0.8){
      Weights[0] = 0.8;
      too_much = 1;
    }
  }else{
    Weights[0] = 0.2;
  }
  for (int i = 1; i < 5; i++)
  {
    if(TotalWeights > 0){
      if(too_much){
        Weights[i] = Weights[i] / TotalWeights * 0.8;
      }else{
        Weights[i] = Weights[i] / TotalWeights;
      }
    }
    else{
      Weights[i] = 0.2;
    }
  }
  if(!has_sub_seed) Weights[0] = 1.0;
  // printf("Weights Total:%f 0:%f 1:%f 2:%f 3:%f 4:%f \n",TotalWeights,Weights[0],Weights[1],Weights[2],Weights[3],Weights[4]);
}

inline void UpdateFeatureFrequency(afl_state_t *afl, struct queue_entry* q) 
{
  // u64 start = get_cur_time();
  q->NeedsEnergyUpdate = 1;

#ifdef WORD_SIZE_64

  u64* current = (u64*)afl->fsrv.trace_bits;

  int  m = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;

  int  m = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  // The local feature frequencies is an ordered vector of pairs.
  // If there are no local feature frequencies, push_back preserves order.
  // Set the feature frequency for feature Idx32 to 1.
  int i = 0, j = 0;
  u32 Idx = 0;
  
  for (i = 0; i < m; i++)
  {
    if (unlikely(*current))
    {
      u8* cur = (u8*)current;
      for (j = 0; j < 8; j++)
      {
        if(unlikely(cur[j]))
        {
          Idx = (i << 3) + j;

          // Global info
          if (GlobalFeatureFreqs[Idx] == 0xFFFF)
            continue;
          u16 Freq  = GlobalFeatureFreqs[Idx]++;

          // Skip if abundant.

          if (Freq > FreqOfMostAbundantRareFeature || (!g_queue_find(RareFeatures, GINT_TO_POINTER(Idx))))
            continue;

          // Update global frequencies.
          if (Freq == FreqOfMostAbundantRareFeature)
            FreqOfMostAbundantRareFeature++; 
          // Global info

          // Local info
          FindRightLocInsert(q->feature_edge, Idx);
        }
      }
    }
    current++;
  }
}

void AddRareFeature(afl_state_t *afl, int Idx)
{
  u32 n = afl->queued_items, i = 0;
  struct queue_entry *q;
  struct queue_entry *q_temp;

  int Idx1,Idx2;
  // printf("RareFeatures Size:%d\n", g_queue_get_length(RareFeatures));
  while (g_queue_get_length(RareFeatures) > MaxNumberOfRarestFeatures &&
         FreqOfMostAbundantRareFeature > FeatureFrequencyThreshold)
  {
    // Find most and second most abbundant feature.
    Idx1 = GPOINTER_TO_INT(g_queue_peek_head(RareFeatures));
    int MostAbundantRareFeatureIndices[2] = {Idx1, Idx1};
    int Delete = 0;
    // Delete_num = 0;
    for (u32 i = 0; i < g_queue_get_length(RareFeatures); i++)
    {
      Idx2 = GPOINTER_TO_INT(g_queue_peek_nth(RareFeatures,i));
      if(GlobalFeatureFreqs[Idx2] >= GlobalFeatureFreqs[MostAbundantRareFeatureIndices[0]]){
        MostAbundantRareFeatureIndices[1] = MostAbundantRareFeatureIndices[0];
        MostAbundantRareFeatureIndices[0] = Idx2;
        Delete = i;
      }
    }
    // Remove most abundant rare feature.
    g_queue_pop_nth(RareFeatures, Delete);
    // RareFeatures[Delete] = -1;
    // NumberOfRareFeatures--;

    // Delete feature Idx and its frequency from FeatureFreqs.

    for (i = 0; i < n; i++)
    {
      q = afl->queue_buf[i];
      // first master seed
      g_hash_table_remove(q->feature_edge, GUINT_TO_POINTER(MostAbundantRareFeatureIndices[0]));
      q->NeedsEnergyUpdate = 1;
      // DeleteFeatureFreq(q, MostAbundantRareFeatureIndices[0]);

      // then sub seed
      q_temp = afl->queue_buf[i+1];
      u8 exit_flag = 0;
      for (int i = 1; i <= 4; i++)
      {
        switch (i)
        {
        case 1:
          if(q->func_seed){
            q = q->func_seed;
          }else
            exit_flag = 1;
          break;
        case 2:
          if(q->ac_seed){
            q = q->ac_seed;
          }else
            exit_flag = 2;
          break;
        case 3:
          if(q->oom_seed){
            q = q->oom_seed;
          }else
            exit_flag = 3;
          break;
        case 4:
          if(q->oob_seed){
            q = q->oob_seed;
          }else
            exit_flag = 4;
          break;
        default:
          break;
        }

        if(exit_flag) {
          exit_flag = 0;
          continue;
        }
        // DeleteFeatureFreq(q, Idx);
        g_hash_table_remove(q->feature_edge, GUINT_TO_POINTER(MostAbundantRareFeatureIndices[0]));
        q->NeedsEnergyUpdate = 1;
      }
      q = q_temp;
    }
    // Set 2nd most abundant as the new most abundant feature count.
    FreqOfMostAbundantRareFeature = GlobalFeatureFreqs[MostAbundantRareFeatureIndices[1]];
  }
  
  // Add rare feature, handle collisions, and update energy.
  // printf("Idx:%d RareFeatures Size:%d\n", Idx ,g_queue_get_length(RareFeatures));
  g_queue_push_tail(RareFeatures, GINT_TO_POINTER(Idx));
  GlobalFeatureFreqs[Idx] = 0;

  for (i = 0; i < n; i++)
  {
    q = afl->queue_buf[i];
    // printf("hash table size:%d\n",g_hash_table_size(q->feature_edge));
    g_hash_table_remove(q->feature_edge, GUINT_TO_POINTER(Idx));
    // printf("hash table size:%d\n",g_hash_table_size(q->feature_edge));
    // DeleteFeatureFreq(q, Idx);
    if(q->Energy > 0.0){
      q->SumIncidence += 1;
      q->Energy += log(q->SumIncidence) / q->SumIncidence;
    }

    // then sub seed
    q_temp = afl->queue_buf[i+1];
    u8 exit_flag = 0;
    for (int i = 1; i <= 4; i++)
    {
      switch (i)
      {
      case 1:
        if(q->func_seed){
          q = q->func_seed;
        }else
          exit_flag = 1;
        break;
      case 2:
        if(q->ac_seed){
          q = q->ac_seed;
        }else
          exit_flag = 2;
        break;
      case 3:
        if(q->oom_seed){
          q = q->oom_seed;
        }else
          exit_flag = 3;
        break;
      case 4:
        if(q->oob_seed){
          q = q->oob_seed;
        }else
          exit_flag = 4;
        break;
      default:
        break;
      }

      if(exit_flag) {
        exit_flag = 0;
        continue;
      }
      // printf("hash table size:%d\n",g_hash_table_size(q->feature_edge));
      g_hash_table_remove(q->feature_edge, GUINT_TO_POINTER(Idx));
      // printf("hash table size:%d\n",g_hash_table_size(q->feature_edge));
      // DeleteFeatureFreq(q, Idx);
      if(q->Energy > 0.0){
        q->SumIncidence += 1;
        q->Energy += log(q->SumIncidence) / q->SumIncidence;
      }
    }
    q = q_temp;
  }
  DistributionNeedsUpdate = 1;
  // time_AddRareFeature += get_cur_time() - start;
}
/* Entropic */

/* BazzAFL */
void destroy_sub_seed(struct queue_entry* q) {

  ck_free(q->fname);
  ck_free(q->trace_mini);
  g_hash_table_destroy(q->feature_edge);
  for (int i = 0; i < 4;i++)
  {
    g_hash_table_destroy(q->feature_metric[i]);
    // ck_free(q->key_byte[i]);
  }
  ck_free(q);
}

void Add_to_Group(afl_state_t *afl, u32 len, u8 new_bits, void *mem)
{

  u8 *fn_mb[4] = {""}, res = 0;
  s32 fd;
  // if(MB_switch)
  // {
  // memset(MB_Features_temp_one, 0, sizeof(MB_Features_temp_one));
  memset(mb_check_ret, 0, sizeof(mb_check_ret));
  struct queue_entry *q = NULL;
  u32 n = afl->queued_items, i = 0;
  // start = get_cur_time();
  // printf("extra shm - trace_bits:%u\n",(u8*)afl->fsrv.extra_shm_ptr - afl->fsrv.trace_bits);
  u32 func_t = afl->fsrv.extra_shm_ptr[0] + afl->fsrv.extra_shm_ptr[1] + afl->fsrv.extra_shm_ptr[2];
  u32 ac_t = afl->fsrv.extra_shm_ptr[3];
  u32 oom_t = afl->fsrv.extra_shm_ptr[4];
  // printf("\n", func_t,ac_t,oom_t);

  float oob_t = (*afl->fsrv.extra_shm_ptr_oob / afl->fsrv.extra_shm_ptr[5]);
  // printf("cksum %llu func:%u\n", cksum_temp, func_t);

  for (i = 0; i < n; i++)
  {
    q = afl->queue_buf[i];

    // printf("func_t:%u ac_t:%u oom_t:%u \nfunc:%u ac:%u oom:%u\n", func_t,ac_t,oom_t,q->max_func_count,q->max_ac_count,q->max_oom_size);
    // printf("cksum %llu vs %llu\n", cksum_temp,q->exec_cksum);
    if(unlikely(q->exec_cksum==cksum_temp)){
      // if(i<n-1){
      //   printf("q.id:%u %u vs %u %u vs%u %u vs %u i:%u n:%u\n", afl->queue_cur->id,q->max_func_count,func_t,q->max_ac_count,ac_t,q->max_oom_size,oom_t,i,n);
      // }
      // if(i<n-1)printf("FUNC %u vs %u id:%u\n", func_t,q->max_func_count,i);
      if(unlikely(func_t > q->max_func_count)){

        q->max_func_count = func_t;
        if(unlikely(q->max_func_count > max_func_count_global)){
          max_func_count_global = q->max_func_count;
        }
        mb_check_ret[0] = 1;
        FindRightLocInsert(afl->queue_cur->feature_metric[0], cksum_temp);
        afl->queue_cur->NeedsEnergyUpdate = 1;
      }

      if(unlikely(ac_t > q->max_ac_count)){

        q->max_ac_count = ac_t;
        if(unlikely(q->max_ac_count > max_ac_count_global)){
          max_ac_count_global = q->max_ac_count;
        }
        mb_check_ret[1] = 1;
        FindRightLocInsert(afl->queue_cur->feature_metric[1], cksum_temp);
        afl->queue_cur->NeedsEnergyUpdate = 1;
      }

      if(unlikely(oom_t > q->max_oom_size)){

        q->max_oom_size = oom_t;
        if(unlikely(q->max_oom_size > max_oom_size_global)){
          max_oom_size_global = q->max_oom_size;
        }
        mb_check_ret[2] = 1;
        FindRightLocInsert(afl->queue_cur->feature_metric[2], cksum_temp);
        afl->queue_cur->NeedsEnergyUpdate = 1;
      }

      if(likely(afl->fsrv.extra_shm_ptr[5]!=0)){
        if(unlikely( oob_t > q->max_oob_total)){

          q->max_oob_total = oob_t;
          if(unlikely(q->max_oob_total > max_oob_total_global)){
            max_oob_total_global = q->max_oob_total;
          }
          mb_check_ret[3] = 1;
          FindRightLocInsert(afl->queue_cur->feature_metric[3], cksum_temp);
          afl->queue_cur->NeedsEnergyUpdate = 1;
        }
      }
      break;
    }
  }

  for(int i = 0;i < 4;i++){

    if(mb_check_ret[i]){

      fn_mb[i] = alloc_printf("%s/mb_seeds/%s/ss%did%dsrc%d_func%d_ac%d_oom%d_oob%f", afl->out_dir, mb_dir_name[i+1], i, NumberOfSubSeed[i], q->id,func_t,ac_t,oom_t,oob_t);
      NumberOfSubSeed[i]++;
      struct queue_entry *q_mb = ck_alloc(sizeof(struct queue_entry)); // flag1
      q_mb->seed_type    = i+1;
      q_mb->fname        = fn_mb[i];
      q_mb->len          = len;
      q_mb->depth        = afl->cur_depth ;
      q_mb->passed_det   = 0;
      q_mb->exec_cksum   = cksum_temp;
      int NumberOfRareFeatures = g_queue_get_length(RareFeatures);
      q_mb->Energy = (NumberOfRareFeatures + afl->queued_items == 0) ? 1.0 : (float)log(NumberOfRareFeatures + afl->queued_items);
      q_mb->SumIncidence = NumberOfRareFeatures + afl->queued_items;
      q_mb->NumExecutedMutations = 0;
      q_mb->feature_edge = g_hash_table_new(g_direct_hash, g_direct_equal);
      q_mb->master_seed = q;

      for (int j = 0; j < 4; j++)
      {
        q_mb->feature_metric[j] = g_hash_table_new(g_direct_hash, g_direct_equal);
      }

      q_mb->NeedsEnergyUpdate = 0;
      if (new_bits == 2) {
        q_mb->has_new_cov = 1;
      }

      res = calibrate_case(afl, q_mb, mem, afl->queue_cycle - 1, 0);
      update_multibugs_seed(q_mb);
      if (res == FSRV_RUN_ERROR)
        FATAL("Unable to execute target application");

      switch (i)
      {
      case 0:
        if(q->func_seed){
          delete_buf[delete_num++] = q->func_seed;
        }
        q->func_seed = q_mb;
        last_func_time = get_cur_time();
        break;
      case 1:
        if(q->ac_seed){
          delete_buf[delete_num++] = q->ac_seed;
        }
        q->ac_seed = q_mb;
        last_ac_time = get_cur_time();
        break;
      case 2:
        if(q->oom_seed){
          delete_buf[delete_num++] = q->oom_seed;
        }
        q->oom_seed = q_mb;
        last_oom_time = get_cur_time();
        break;
      case 3:
        if(q->oob_seed){
          delete_buf[delete_num++] = q->oob_seed;
        }
        q->oob_seed = q_mb;
        last_oob_time = get_cur_time();
        break;                            
      default:
        break;
      }

      fd = open(fn_mb[i], O_WRONLY | O_CREAT | O_EXCL , DEFAULT_PERMISSION);
      if (fd < 0) PFATAL("Unable to create '%s'", fn_mb[i]);
      ck_write(fd, mem, len, fn_mb[i]);
      close(fd);

      afl->pending_not_fuzzed++;
      
    }

  }

}

/* BazzAFL */
/* Byte Inference */

u32 byte_orig_func = 0;
u32 byte_orig_ac = 0;
u32 byte_orig_oom = 0;
float byte_orig_oob = 0.0;
u32 byte_cur_func=0;
u32 byte_cur_ac=0;
u32 byte_cur_oom=0;
float byte_cur_oob=0.0;

void zip_byte_infer(afl_state_t *afl, int metric_type, u8 *temp_key_byte_lookup,u8 *temp_key_byte_orig,u8 *out_buf,u32 temp_len)
{

  u8 temp_buf;
  u8 exit_soon = 0;

  for (u32 i = 0; i < temp_len; i++)
  {
    if(exit_soon == 1){
      break; // find a byte which is the only related about 'metric_type' metric
    }
    if(unlikely(temp_key_byte_lookup[i] == 1)) // possible byte
    {

      temp_buf = out_buf[i];
      out_buf[i] = temp_key_byte_orig[i]; // return to original byte value
      if (common_fuzz_stuff(afl, out_buf, temp_len)){}
      switch (metric_type){
        case 1:{
          if(unlikely(cksum_temp == afl->queue_cur->exec_cksum) && likely(cksum_temp)){

            if(afl->fsrv.extra_shm_ptr[0] + afl->fsrv.extra_shm_ptr[1] + afl->fsrv.extra_shm_ptr[2] == byte_cur_func)
            {
              g_queue_remove(afl->queue_cur->key_byte[0], GINT_TO_POINTER(i));
            }
            else
            {
              if(unlikely(afl->fsrv.extra_shm_ptr[0] + afl->fsrv.extra_shm_ptr[1] + afl->fsrv.extra_shm_ptr[2] == byte_orig_func)){
                g_queue_push_tail(afl->queue_cur->key_byte[0], GINT_TO_POINTER(i));
                exit_soon = 1;
              }else{
                g_queue_push_tail(afl->queue_cur->key_byte[0], GINT_TO_POINTER(i));
              }

            }
          }
          break;
        }
        case 2:{
          if(unlikely(cksum_temp == afl->queue_cur->exec_cksum) && likely(cksum_temp)){

            if(afl->fsrv.extra_shm_ptr[3] == byte_cur_ac)
            {
              g_queue_remove(afl->queue_cur->key_byte[1], GINT_TO_POINTER(i));
            }
            else
            {
              if(afl->fsrv.extra_shm_ptr[3] == byte_orig_ac){
                g_queue_push_tail(afl->queue_cur->key_byte[1], GINT_TO_POINTER(i));
                exit_soon = 1;
              }else{
                g_queue_push_tail(afl->queue_cur->key_byte[1], GINT_TO_POINTER(i));
              }

            }
          }
          break;
        }
        case 3:{
          if(unlikely(cksum_temp == afl->queue_cur->exec_cksum) && likely(cksum_temp)){

            if(afl->fsrv.extra_shm_ptr[4] == byte_cur_oom)
            {
              g_queue_remove(afl->queue_cur->key_byte[2], GINT_TO_POINTER(i));
            }
            else
            {
              if(afl->fsrv.extra_shm_ptr[4] == byte_orig_oom){
                g_queue_push_tail(afl->queue_cur->key_byte[2], GINT_TO_POINTER(i));
                exit_soon = 1;
              }else{
                g_queue_push_tail(afl->queue_cur->key_byte[2], GINT_TO_POINTER(i));
              }

            }
          }          
          break;
        }
        case 4:{
          if(unlikely(cksum_temp == afl->queue_cur->exec_cksum) && likely(cksum_temp)){

            float temp_oob = 0.0;
            if (likely(afl->fsrv.extra_shm_ptr[5] != 0))
            {
              temp_oob = (*afl->fsrv.extra_shm_ptr_oob / afl->fsrv.extra_shm_ptr[5]);
            }
            else
            {
              temp_oob = 0;
            }
            if(temp_oob == byte_cur_oob)
            {
              g_queue_remove(afl->queue_cur->key_byte[3], GINT_TO_POINTER(i));
            }
            else
            {
              if(temp_oob == byte_orig_oob){
                g_queue_push_tail(afl->queue_cur->key_byte[3], GINT_TO_POINTER(i));
                exit_soon = 1;
              }else{
                g_queue_push_tail(afl->queue_cur->key_byte[3], GINT_TO_POINTER(i));
              }

            }
          }
          break;
        }
        default:
          break;
      }
      out_buf[i] = temp_buf;
    }
  }

}

/* 
  BazzAFL
*/